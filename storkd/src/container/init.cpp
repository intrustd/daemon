#include <boost/log/trivial.hpp>

#include <iostream>
#include <sstream>
#include <cstring>
#include <thread>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "init.hpp"

namespace stork {
  namespace container {
    ContainerService::ContainerService(int comm_fd)
      : m_comm_fd(comm_fd) {
    }

    ContainerService::~ContainerService() {
      close(m_comm_fd);
    }

    void ContainerService::handshake(int tun_fd) {
      std::uint8_t cbuf[CMSG_SPACE(int)];

      std::uint32_t cookie = 0xDEADBEEF;
      struct iovec io[] = { { .iov_base = &cookie, .iov_len = sizeof(cookie) } };
      struct msghdr msg = { 0 };
      msg.msg_iov = io;
      msg.msg_iovlen = 1;
      msg.msg_control = cbuf;
      msg.msg_controllen = sizeof(cbuf);

      struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
      cmsg->cmsg_level = SOL_SOCKET;
      cmsg->cmsg_type  = SCM_RIGHTS;
      cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
      int *tun_fd_ptr = (int *) CMSG_DATA(cmsg);
      *tun_fd_ptr = tun_fd; // TODO use tun_fd

      msg.msg_controllen = cmsg->cmsg_len;

      int err = sendmsg(m_comm_fd, &msg, 0);
      if ( err < 0 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not transfer tun FD: " << ec;
      }

      // Wait for reply to close tun descriptor
      msg.msg_control = NULL;
      msg.msg_controllen = 0;

      err = recvmsg(m_comm_fd, &msg, 0);
      if ( err < 0 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not read ack: " << ec;
      }
    }


    void ContainerService::serve() {
      
    }

    // Init

    Init::Init(int argc, const char **argv)
      : m_tun_fd(-1), m_comm_fd(-1) {

#define NEXT_ARG(flag) if ( (i + 1) < argc ) { i++; arg << argv[i]; } else usage("Expected argument for " # flag);
      for ( int i = 0; i < argc; ++i ) {
        std::stringstream arg;
        if ( strcmp(argv[i], "--comm") == 0 ) {
          NEXT_ARG("--comm");
          arg >> m_comm_fd;
        } else if ( strcmp(argv[i], "--tun") == 0 ) {
          NEXT_ARG("--tun");
          arg >> m_tun_fd;
        } else {
          std::stringstream err;
          err << "Unrecognized flag: " << argv[i];
          usage(err.str().c_str());
        }
      }
#undef NEXT_ARG
    }

    int Init::run() {
      if ( !is_valid() )
        usage("No TUN or comm descriptor provided");

      // First thing to do is to send TUN device over to the main server
      ContainerService master(m_comm_fd);

      master.handshake(m_tun_fd);

      int tun_fd(-1);
      std::swap(tun_fd, m_tun_fd); // TODO atomic?
      close(tun_fd);

      // Start the init service message handler in a separate thread
      std::thread service_comm([&master]() { master.serve(); });

      // Run the init process

      // Bring up units based on our current application state
      // The application state determines which units can run.
      //
      // If the state name is empty, the state is assumed to be install
      //
      // The current state can be read from the file /stork/app/state.
      //
      // Within each state, it is expected we will find one main
      // 'service'. A service is a program that must stay alive during
      // the entirety of that state.
      //
      // If the main service exits successfully, then we will check if
      // the state has changed. If the state has not changed, then we
      // exit this container. If the state has changed, then we
      // upgrade to the next state
      //
      // States are persisted between runs of containers.


      return 0;
    }

    void Init::usage(const char *err) const {
      std::cerr << err << std::endl;
      std::cerr << "stork-init -- Init program for stork containers" << std::endl;
      std::cerr << "Usage: stork-init --tun <tun-fd> --comm <comm-fd>" << std::endl;
      std::cerr << std::endl;
      std::cerr << " Flags:" << std::endl;;
      std::cerr << "  --tun <tun-fd>    TUN device file descriptor" << std::endl;
      std::cerr << "  --comm <comm-fd>  Communication port with storkd" << std::endl;
      exit(1);
    }
  }
}

