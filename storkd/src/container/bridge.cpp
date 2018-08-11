#include <boost/log/trivial.hpp>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sstream>

#include "bridge.hpp"

namespace stork {
  namespace container {
    struct bridge_main_info {
      BridgeController *controller;
      uid_t root_uid;
      gid_t root_gid;
      int comm_fd[2];
    };

    BridgeController::BridgeController(nix::NixStore &nix)
      : m_nix_store(nix), m_netns_fd(0), m_userns_fd(0) {
      // The bridge controller operates in a separate namespace.
      // We have to use 'clone()' to launch that namespace.

      struct bridge_main_info main_info = { .controller = this,
                                            .root_uid = getuid(),
                                            .root_gid = getgid() };
      int err = socketpair(AF_UNIX, SOCK_DGRAM, 0, main_info.comm_fd);
      if ( err < 0 ) {
        BOOST_LOG_TRIVIAL(error) << "BridgeController: Could not create socket pair";
        return;
      }

      std::vector<std::uint8_t> stack;
      stack.resize(4096);

      int new_proc =
        clone(&BridgeController::main, stack.data() + stack.size(),
              CLONE_NEWUSER | CLONE_NEWNET | CLONE_VFORK, &main_info);
      if ( new_proc == -1 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not clone bridge controller process in new namespace: "
                                 << ec;
        return;
      }

      close(main_info.comm_fd[0]);

      // Attempt to read the network namespace out of the child
      std::uint8_t cbuf[CMSG_SPACE(sizeof(int) * 2)];
      struct msghdr msg = { 0 };
      msg.msg_iov = nullptr;
      msg.msg_iovlen = 0;
      msg.msg_control = cbuf;
      msg.msg_controllen = sizeof(cbuf);

      err = recvmsg(main_info.comm_fd[1], &msg, 0);
      if ( err < 0 ) {
        auto ec(errno);
        close(main_info.comm_fd[1]);
        BOOST_LOG_TRIVIAL(error) << "BridgeController: could not capture network namespace fd: " << ec;
        return;
      }

      struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
      if ( !cmsg || cmsg->cmsg_level != SOL_SOCKET ||
           cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len != CMSG_LEN(sizeof(int) * 2) ) {
        close(main_info.comm_fd[1]);
        BOOST_LOG_TRIVIAL(error) << "BridgeController: malformed message returned";
        return;
      }

      m_netns_fd = *((int *)CMSG_DATA(cmsg));
      m_userns_fd = *(((int *)CMSG_DATA(cmsg)) + 1);
      BOOST_LOG_TRIVIAL(info) << "Network namespace fd is " << m_netns_fd;
      BOOST_LOG_TRIVIAL(info) << "User namespace fd is " << m_userns_fd;

      close(main_info.comm_fd[1]);

      // Make sure both these file descriptors close on exec
      fcntl(m_netns_fd, F_SETFD, FD_CLOEXEC);
      fcntl(m_userns_fd, F_SETFD, FD_CLOEXEC);

      //create_veth_pair("stork0", "stork");
      // Attach stork-out to network namespace
    }

    BridgeController::~BridgeController() {
      if ( m_netns_fd ) close(m_netns_fd);
      if ( m_userns_fd ) close(m_userns_fd);
    }

    int BridgeController::main(void *comm_ptr) {
      struct bridge_main_info *main_info((struct bridge_main_info *)comm_ptr);
      close(main_info->comm_fd[1]);

      FILE *gid_map(fopen("/proc/self/gid_map", "wt"));
      if ( !gid_map ) return 1;
      fprintf(gid_map, "0 %d 1\n", main_info->root_gid);
      fclose(gid_map);

      FILE *uid_map(fopen("/proc/self/uid_map", "wt"));
      if ( !uid_map ) return 1;
      fprintf(uid_map, "0 %d 1\n", main_info->root_uid);
      fclose(uid_map);

      BOOST_LOG_TRIVIAL(debug) << "Creating bridge";
      auto iproute((main_info->controller->m_nix_store["iproute"] / "bin" / "ip").string());

      std::stringstream cmd;
      cmd << iproute << " link add bridge type bridge";
      int err = system(cmd.str().c_str());
      if ( err != 0 ) {
        BOOST_LOG_TRIVIAL(debug) << cmd.str() << ": exited with " << err;
        return 1;
      }

      cmd.str("");
      cmd << iproute << " link set dev lo up";
      err = system(cmd.str().c_str());
      if ( err != 0 ) {
        BOOST_LOG_TRIVIAL(debug) << "Could not bring up lo: " << err;
        return 1;
      }

      cmd.str("");
      cmd << iproute << " link set dev bridge up";
      err = system(cmd.str().c_str());
      if ( err != 0 ) {
        BOOST_LOG_TRIVIAL(debug) << "Could not bring up bridge: " << err;
        return 1;
      }

      // Send the network namespace back to the main thread
      int netns_fd = open("/proc/self/ns/net", 0);
      if ( netns_fd < 0 ) {
        BOOST_LOG_TRIVIAL(error) << "Could not open network namespace";
        return 1;
      }

      int userns_fd = open("/proc/self/ns/user", 0);
      if ( userns_fd < 0 ) {
        BOOST_LOG_TRIVIAL(error) << "Could not open user namespace";
        return 1;
      }

      // Send namespace back
      std::uint8_t cbuf[CMSG_SPACE(sizeof(int) * 2)];
      struct msghdr msg = { 0 };
      msg.msg_iov = nullptr;
      msg.msg_iovlen = 0;
      msg.msg_control = cbuf;
      msg.msg_controllen = sizeof(cbuf);

      struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
      cmsg->cmsg_level = SOL_SOCKET;
      cmsg->cmsg_type = SCM_RIGHTS;
      cmsg->cmsg_len = CMSG_LEN(sizeof(int) * 2);
      *((int *) CMSG_DATA(cmsg)) = netns_fd;
      *(((int *) CMSG_DATA(cmsg)) + 1) = userns_fd;

      err = sendmsg(main_info->comm_fd[0], &msg, 0);
      if ( err < 0 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not transfer bridge FDs: " << ec;
        return 1;
      }

      return 0;
    }
  }
}
