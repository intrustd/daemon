#include <boost/log/utility/manipulators/dump.hpp>
#include <boost/log/trivial.hpp>
#include <boost/bind.hpp>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sstream>
#include <fstream>
#include <iostream>

#include <openssl/hmac.h>

#include <storkd_proto.h>

#include "../util/fd.hpp"
#include "../util/array.hpp"
#include "../random.hpp"
#include "../proto.hpp"
#include "app_instance.hpp"
#include "ethernet.hpp"
#include "bridge.hpp"
#include "runtime.hpp"
#include "manager.hpp"

namespace stork {
  namespace container {
    struct bridge_main_info {
      BridgeController *controller;
      uid_t root_uid;
      gid_t root_gid;
      int comm_fd[2];
    };

    class AppInstanceResolver {
    public:
      AppInstanceResolver(BridgeController &recipient, Manager &cmgr, backend::IBackend &be,
                          const boost::asio::ip::address_v4 &dest, std::uint16_t dest_port,
                          const std::string &app_uri_raw)
        : m_bridge(recipient), m_containers(cmgr), m_backend(be),
          m_dest(dest), m_dest_port(dest_port), m_valid(false), m_app_id("", "") {
        uri::Uri app_uri(app_uri_raw);
        if ( app_uri.is_valid() )
          m_app_id = application::ApplicationIdentifier::from_canonical_url(app_uri, m_valid);
      }
      virtual ~AppInstanceResolver() { };

      inline bool is_valid() const { return m_valid; }
      inline const application::ApplicationIdentifier &for_app() const { return m_app_id; }
      inline BridgeController &recipient() { return m_bridge; }

      void async_resolve() {
        m_containers.async_build_and_launch_app_instance
          (app_instance_id(),
           boost::bind(&AppInstanceResolver::with_container, base_shared_from_this(),
                       boost::placeholders::_1, boost::placeholders::_2));
      }

    protected:
      virtual std::shared_ptr<AppInstanceResolver> base_shared_from_this() =0;
      virtual AppInstanceId app_instance_id() const =0;

      inline Manager &containers() { return m_containers; }
      inline backend::IBackend &backend() { return m_backend; }

      void report_error(std::uint32_t err) {
        struct stkdmsg rsp;
        rsp.sm_flags = STKD_MKFLAGS(STKD_RSP | STKD_ERROR, STKD_OPEN_APP_REQUEST);
        rsp.sm_data.sm_error = htonl(err);

        recipient().write_udp_packet(BridgeController::STORKD_INTERNAL_UDP_PORT, m_dest_port,
                                     m_dest,
                                     boost::asio::buffer(&rsp, STKD_ERROR_MSG_SZ));
      }

    private:
      void with_container(std::error_code ec, std::shared_ptr<AppInstanceMonitor> cm) {
        if ( ec ) {
          BOOST_LOG_TRIVIAL(debug) << "App instance resolution fails because " << ec << " while launching container";
        } else {
          BOOST_LOG_TRIVIAL(debug) << "App instance resolution succeeds: " << cm->owner().ip_address();
          struct stkdmsg rsp;

          rsp.sm_flags = STKD_MKFLAGS(STKD_RSP, STKD_OPEN_APP_REQUEST);
          rsp.sm_data.sm_opened_app.sm_family = htonl(AF_INET);
          rsp.sm_data.sm_opened_app.sm_addr = htonl(cm->owner().ip_address().to_ulong());

          recipient().write_udp_packet(BridgeController::STORKD_INTERNAL_UDP_PORT, m_dest_port,
                                       m_dest,
                                       boost::asio::buffer(&rsp, STKD_OPENED_APP_RSP_SZ));
        }
      }

      BridgeController &m_bridge;
      Manager &m_containers;
      backend::IBackend &m_backend;

      boost::asio::ip::address_v4 m_dest;
      std::uint16_t m_dest_port;

      bool m_valid;
      application::ApplicationIdentifier m_app_id;
    };

    class AppInstanceForPersonaResolver : public std::enable_shared_from_this<AppInstanceForPersonaResolver>,
                                          public AppInstanceResolver {
    public:
      AppInstanceForPersonaResolver(BridgeController &r, Manager &cmgr, backend::IBackend &be,
                                    const boost::asio::ip::address_v4 &dest, std::uint16_t dest_port,
                                    const backend::PersonaId &pid,
                                    const std::string &app_uri_raw)
        : AppInstanceResolver(r, cmgr, be, dest, dest_port, app_uri_raw),
          m_persona_id(pid) {
      }
      virtual ~AppInstanceForPersonaResolver() {
        BOOST_LOG_TRIVIAL(debug) << "Done resolving app instance for persona";
      }

      inline const backend::PersonaId &for_persona() const { return m_persona_id; }

      void async_resolve() {
        if ( is_valid() ) {
          // Check to see if this persona has access rights to this app instance
          backend().async_get_persona
            (for_persona(),
             boost::bind(&AppInstanceForPersonaResolver::on_persona,
                         shared_from_this(), boost::placeholders::_1));
        } else {
          report_error(STKD_ERROR_MALFORMED_NAME);
        }
      }

    protected:
      virtual std::shared_ptr<AppInstanceResolver> base_shared_from_this() override {
        return shared_from_this();
      }

      virtual AppInstanceId app_instance_id() const override {
        return AppInstanceId(for_persona(), for_app());
      }

      void on_persona(std::shared_ptr<backend::IPersona> p) {
        m_backend_persona = p;
        if ( p ) {
          p->async_check_application_installed
            (for_app(),
             boost::bind(&AppInstanceForPersonaResolver::on_application_check, shared_from_this(), boost::placeholders::_1));
        } else {
          report_error(STKD_ERROR_PERSONA_DOES_NOT_EXIST);
        }
      }

      void on_application_check(bool is_installed) {
        if ( is_installed ) {
          // Since the application is installed, we will allow the
          // resolver to load the app container, and find the IP
          // address
          AppInstanceResolver::async_resolve();
        } else {
          report_error(STKD_ERROR_APP_NOT_INSTALLED);
        }
      }

    private:
      backend::PersonaId m_persona_id;

      std::shared_ptr<backend::IPersona> m_backend_persona;
    };

    std::array<std::uint8_t, ETH_ALEN> BridgeController::find_hw_addr(const std::string &if_name,
                                                                      std::error_code &ec) {
      ec = std::error_code();

      std::array<std::uint8_t, ETH_ALEN> ret;

      int sk(socket(AF_UNIX, SOCK_DGRAM, 0));
      if ( sk == -1 ) {
        ec = std::error_code(errno, std::generic_category());
        return ret;
      }

      struct ifreq ifr;
      *std::copy(if_name.begin(), if_name.end(), ifr.ifr_name) = '\0';
      if ( ioctl(sk, SIOCGIFHWADDR, &ifr, sizeof(ifr)) == -1 ) {
        ec = std::error_code(errno, std::generic_category());
        close(sk);
        return ret;
      }

      if ( ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER ) {
        ec = std::make_error_code(std::errc::invalid_argument);
        close(sk);
        return ret;
      }

      std::copy(ifr.ifr_hwaddr.sa_data, ifr.ifr_hwaddr.sa_data + ETH_ALEN,
                ret.begin());

      close(sk);

      return ret;
    }

    BridgeController::BridgeController(boost::asio::io_service &svc, nix::NixStore &nix,
                                       Manager &cmgr, backend::IBackend &be)
      : m_service(svc), m_nix_store(nix), m_container_mgr(cmgr), m_backend(be),
        m_cap_key(util::random_string(512)),
        m_netns_fd(0), m_userns_fd(0),
        m_tap_stream(svc), m_eth_ix(0), m_next_ip(0x0A000001) {

      std::fstream dbg("logged.pkts", std::fstream::out);
      enable_logging(std::move(dbg));

      // The bridge controller operates in a separate namespace.
      // We have to use 'clone()' to launch that namespace.
      m_bridge_addr = next_ip();

      // Taken from linux's routine eth_random_addr
      std::copy(util::random_iterator<std::uint8_t>(ETH_ALEN),
                util::random_iterator<std::uint8_t>(),
                m_stork_mac.begin());
      m_stork_mac[0] &= 0xFE; // Clear multicast bit
      m_stork_mac[1] |= 0x02; // Local assignment bit

      struct bridge_main_info main_info = { .controller = this,
                                            .root_uid = getuid(),
                                            .root_gid = getgid() };
      int err = socketpair(AF_UNIX, SOCK_DGRAM, 0, main_info.comm_fd);
      if ( err < 0 ) {
        BOOST_LOG_TRIVIAL(error) << "BridgeController: Could not create socket pair";
        return;
      }

      std::vector<std::uint8_t> stack;
      stack.resize(8192);

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
      int ns_fds[3];
      std::error_code recv_err(recv_fd(main_info.comm_fd[1], 3, ns_fds));
      if ( recv_err ) {
        close(main_info.comm_fd[1]);
        BOOST_LOG_TRIVIAL(error) << "BridgeController: could not receive fds: " << recv_err;
        return;
      }
//      std::uint8_t cbuf[CMSG_SPACE(sizeof(int) * 2)];
//      struct msghdr msg = { 0 };
//      msg.msg_iov = nullptr;
//      msg.msg_iovlen = 0;
//      msg.msg_control = cbuf;
//      msg.msg_controllen = sizeof(cbuf);
//
//      err = recvmsg(main_info.comm_fd[1], &msg, 0);
//      if ( err < 0 ) {
//        auto ec(errno);
//        close(main_info.comm_fd[1]);
//        BOOST_LOG_TRIVIAL(error) << "BridgeController: could not capture network namespace fd: " << ec;
//        return;
//      }
//
//      struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
//      if ( !cmsg || cmsg->cmsg_level != SOL_SOCKET ||
//           cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len != CMSG_LEN(sizeof(int) * 2) ) {
//        close(main_info.comm_fd[1]);
//        BOOST_LOG_TRIVIAL(error) << "BridgeController: malformed message returned";
//        return;
//      }

      m_netns_fd = ns_fds[0]; //*((int *)CMSG_DATA(cmsg));
      m_userns_fd = ns_fds[1]; // *(((int *)CMSG_DATA(cmsg)) + 1);
      int tap_fd(ns_fds[2]);
      BOOST_LOG_TRIVIAL(info) << "Network namespace fd is " << m_netns_fd;
      BOOST_LOG_TRIVIAL(info) << "User namespace fd is " << m_userns_fd;
      BOOST_LOG_TRIVIAL(info) << "Tap fd is " << tap_fd;

      close(main_info.comm_fd[1]);

      // Make sure both these file descriptors close on exec
      fcntl(m_netns_fd, F_SETFD, FD_CLOEXEC);
      fcntl(m_userns_fd, F_SETFD, FD_CLOEXEC);
      fcntl(tap_fd, F_SETFD, FD_CLOEXEC);

      err = fcntl(tap_fd, F_GETFL, 0);
      if ( err == -1 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not get tap flags: " << ec;
        return;
      }

      fcntl(tap_fd, F_SETFL, err | O_NONBLOCK);

      // Now let's launch the TAP reader
      boost::system::error_code ec;
      m_tap_addr = next_ip();
      m_tap_stream.assign(tap_fd, ec);
      if ( ec ) {
        BOOST_LOG_TRIVIAL(error) << "Could not assign tap reader: " << ec;
        return;
      }

      // Start TAP reader
      read_tap(1500);
    }

    BridgeController::~BridgeController() {
      if ( m_netns_fd ) close(m_netns_fd);
      if ( m_userns_fd ) close(m_userns_fd);
    }

    int BridgeController::main(void *comm_ptr) {
      struct bridge_main_info *main_info((struct bridge_main_info *)comm_ptr);
      close(main_info->comm_fd[1]);

      std::fstream deny_setgroups("/proc/self/setgroups", std::fstream::out);
      deny_setgroups << "deny";
      deny_setgroups.close();

      std::fstream gid_map("/proc/self/gid_map", std::fstream::out);
      gid_map << "0 " << main_info->root_gid << " 1" << std::endl;
      gid_map.close();

      std::fstream uid_map("/proc/self/uid_map", std::fstream::out);
      uid_map << "0 " << main_info->root_uid << " 1" << std::endl;
      uid_map.close();

      BOOST_LOG_TRIVIAL(debug) << "Creating bridge";
      auto iproute((main_info->controller->m_nix_store["iproute"] / "bin" / "ip").string());

      BOOST_LOG_TRIVIAL(debug) << "Setting uid";

      int err;
      err = setreuid(0, 0);
      if ( err < 0 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not set UID: " << ec;
        return 1;
      }
      BOOST_LOG_TRIVIAL(debug) << "Set uid";

      err = setregid(0, 0);
      if ( err < 0 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not set GID: " << ec;
        return 1;
      }

      std::stringstream cmd;
      cmd << iproute << " link add bridge type bridge";
      err = system(cmd.str().c_str());
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

      // Create TUN device, and add to bridge
      TunDevice tap(true);
      BOOST_LOG_TRIVIAL(info) << "Created tap device: " << tap.device_name();
      cmd.str("");
      cmd << iproute << " link set dev " << tap.device_name() << " master bridge";
      err = system(cmd.str().c_str());
      if ( err != 0 ) {
        BOOST_LOG_TRIVIAL(debug) << "Could not set tap master: " << err;
        return 1;
      }

      cmd.str("");
      cmd << iproute << " link set dev " << tap.device_name() << " up multicast off";
      err = system(cmd.str().c_str());
      if ( err != 0 ) {
        BOOST_LOG_TRIVIAL(debug) << "Could not set tap up: " << err;
        return 1;
      }

      cmd.str("");
      cmd << iproute << " link set dev bridge up multicast off";
      err = system(cmd.str().c_str());
      if ( err != 0 ) {
        BOOST_LOG_TRIVIAL(debug) << "Could not bring up bridge: " << err;
        return 1;
      }

      BOOST_LOG_TRIVIAL(debug) << "Bridge namespace networks: ";
      // system("ip link show");
      //      system("ifconfig -a");

      // Send the network namespace back to the main thread
      int netns_fd(open("/proc/self/ns/net", 0));
      if ( netns_fd < 0 ) {
        BOOST_LOG_TRIVIAL(error) << "Could not open network namespace";
        return 1;
      }

      int userns_fd(open("/proc/self/ns/user", 0));
      if ( userns_fd < 0 ) {
        BOOST_LOG_TRIVIAL(error) << "Could not open user namespace";
        return 1;
      }

      // Send namespace back
      int ns_fds[3] = { netns_fd, userns_fd, tap.steal() };
      std::error_code send_err(send_fd(main_info->comm_fd[0], 3, ns_fds));
      if ( send_err ) {
        BOOST_LOG_TRIVIAL(error) << "Could not transfer bridge FDs: " << send_err;
        return 1;
      }

      return 0;
    }

    std::error_code BridgeController::set_up_networking() {
      auto iproute((m_nix_store["iproute"] / "bin" / "ip").string());
      std::stringstream cmd;
      cmd << iproute << " link set dev lo up";
      int err = system(cmd.str().c_str());
      if ( err != 0 ) {
        BOOST_LOG_TRIVIAL(error) << "Could not set up networking: " << cmd.str() << " returns: " << err;
      }

      return std::error_code();
    }

    void BridgeController::send_arp_entry_over_socket(int comm, const ArpEntry &arp) {
      struct {
        std::uint32_t ip;
        std::uint8_t hw_addr[ETH_ALEN];
      } __attribute__((packed)) pkt;

      pkt.ip = arp.first;
      std::copy(arp.second.begin(), arp.second.end(), pkt.hw_addr);

      int err(send(comm, &pkt, sizeof(pkt), 0));
      if ( err == -1 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not send arp entry over socket: " << ec;
      }

      assert(err == sizeof(pkt));
    }

    BridgeController::ArpEntry BridgeController::add_arp_from_socket(int comm) {
      struct {
        std::uint32_t ip;
        std::uint8_t hw_addr[ETH_ALEN];
      } __attribute__((packed)) pkt;

      int err(recv(comm, &pkt, sizeof(pkt), 0));
      if ( err == -1 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not read arp entry from socket: " << ec;
        return ArpEntry();
      } else if ( err != sizeof(pkt) ) {
        BOOST_LOG_TRIVIAL(error) << "Could not read arp entry from socket: incorrect packet size";
        return ArpEntry();
      }

      std::array<std::uint8_t, ETH_ALEN> hw_addr;
      std::copy(pkt.hw_addr, pkt.hw_addr + ETH_ALEN, hw_addr.begin());

      boost::asio::ip::address_v4 ip_asio(pkt.ip);
      add_arp_entry(ip_asio, hw_addr);

      std::uint32_t ip(pkt.ip);
      return ArpEntry(ip, hw_addr);
    }

    BridgePort BridgeController::allocate_port() {
      boost::unique_lock l(m_veth_mutex);
      int this_eth_ix(m_eth_ix++);
      return this_eth_ix;
    }

    boost::asio::ip::address_v4 BridgeController::allocate_ip() {
      boost::unique_lock l(m_veth_mutex);
      std::uint32_t this_ip(m_next_ip++);
      return boost::asio::ip::address_v4(this_ip);
    }

    std::error_code BridgeController::create_veth_to_ns(int netns_fd,
                                                        BridgePort port_ix,
                                                        const boost::asio::ip::address_v4 &this_ip_v4,
                                                        const std::string &if_name,
                                                        ArpEntry &entry) {
      BOOST_LOG_TRIVIAL(debug) << "Creating veth to " << netns_fd << ": " << if_name;

      // TODO is this necessary??
      boost::unique_lock l(m_veth_mutex);
      int this_eth_ix(port_ix.port);

      std::stringstream in_if_name, out_if_name;
      out_if_name << "out" << this_eth_ix;
      in_if_name << "in" << this_eth_ix;

      int comm_fd[2];
      int err(socketpair(AF_UNIX, SOCK_DGRAM, 0, comm_fd));
      if ( err < 0 ) {
        return std::error_code(errno, std::generic_category());
      }

      pid_t new_proc(fork());
      if ( new_proc == -1 ) {
        return std::error_code(errno, std::generic_category());
      } else if ( new_proc == 0 ) {
        close(comm_fd[1]);

        err = enter_network_namespace();
        if ( err < 0 ) exit(-err);

        err = create_veth(in_if_name.str(), out_if_name.str());
        if ( err < 0 ) exit(-err);

        err = move_if_to_ns(out_if_name.str(), netns_fd);
        if ( err < 0 ) exit(-err);

        //        system("ifconfig -a");

        std::uint8_t sts(1);
        err = send(comm_fd[0], &sts, 1, 0);
        if ( err == -1)
          exit(err);

        // Now move this interface no the other network namespace

        exit(0);
      } else {
        close(comm_fd[0]);

        std::uint8_t sts;
        err = recv(comm_fd[1], &sts, 1, 0);
        if ( err == -1 ) {
          close(comm_fd[1]);
          return std::error_code(errno, std::generic_category());
        }
        close(comm_fd[1]);

        // Now that we're back in our namespace, we should rename the interface to the correct name
        std::stringstream cmd;
        auto iproute((m_nix_store["iproute"] / "bin" / "ip").string());
        cmd << iproute << " link set " << out_if_name.str() << " name " << if_name << " multicast off";
        err = system(cmd.str().c_str());
        if ( err != 0 ) {
          BOOST_LOG_TRIVIAL(error) << "Could not run " << cmd.str() << ": " << err;
          return std::error_code(EINVAL, std::generic_category());
        }

        cmd.str("");
        cmd << iproute << " address add " << this_ip_v4 << "/8 broadcast 10.255.255.255 dev " << if_name;
        err = system(cmd.str().c_str());
        if ( err != 0 ) {
          BOOST_LOG_TRIVIAL(error) << "Could not run " << cmd.str() << ": " << err;
          return std::error_code(EINVAL, std::generic_category());
        }

        // cmd.str("");
        // cmd << iproute << " route flush dev " << if_name;
        // err = system(cmd.str().c_str());
        // if ( err != 0 ) {
        //   BOOST_LOG_TRIVIAL(error) << "Could not run " << cmd.str() << ": " << err;
        //   return std::error_code(EINVAL, std::generic_category());
        // }

        // cmd.str("");
        // cmd << iproute << " route add " << this_ip_v4 << "/8 dev " << if_name;
        // err = system(cmd.str().c_str());
        // if ( err != 0 ) {
        //   BOOST_LOG_TRIVIAL(error) << "Could not run " << cmd.str() << ": " << err;
        //   return std::error_code(EINVAL, std::generic_category());
        // }

        // cmd.str("");
        // cmd << iproute << " route add default via " << m_bridge_addr;
        // err = system(cmd.str().c_str());
        // if ( err != 0 ) {
        //   BOOST_LOG_TRIVIAL(error) << "Could not run " << cmd.str() << ": " << err;
        //   return std::error_code(EINVAL, std::generic_category());
        // }


        cmd.str("");
        cmd << iproute << " link set dev " << if_name << " up";
        err = system(cmd.str().c_str());
        if ( err != 0 ) {
          BOOST_LOG_TRIVIAL(error) << "Could not run " << cmd.str() << ": " << err;
          return std::error_code(EINVAL, std::generic_category());
        }

        // We also want to get the hardware address of this interface
        std::error_code find_hw_ec;
        auto hw_addr(find_hw_addr(if_name, find_hw_ec));
        if ( find_hw_ec ) {
          BOOST_LOG_TRIVIAL(error) << "Could not find hardware address for " << if_name << ": " << find_hw_ec;
          return find_hw_ec;
        }

        entry = std::make_pair(this_ip_v4.to_ulong(), hw_addr);

        return std::error_code();
      }
    }

    boost::asio::ip::address_v4 BridgeController::next_ip() {
      return boost::asio::ip::address_v4(m_next_ip++);
    }

    int BridgeController::enter_network_namespace() {
      // Set network namespace to our network namespace
      int err;

      // err = setns(m_userns_fd, CLONE_NEWUSER);
      // if ( err == -1 ) {
      //   err = errno;
      //   BOOST_LOG_TRIVIAL(error) << "Could not set user namespace: " << err;
      //   return -err;
      // }

      err = setns(m_netns_fd, CLONE_NEWNET);
      if ( err == -1 ) {
        err = errno;
        BOOST_LOG_TRIVIAL(error) << "Could not set network namespace: " << err;
        return -err;
      }

      BOOST_LOG_TRIVIAL(debug) << "Entered namespace with uid " << getuid() << " and gid " << getgid();

      return 1;
    }

    int BridgeController::create_veth(const std::string &in_if_name,
                                      const std::string &out_if_name) {
      // Create veth pair
      auto iproute((m_nix_store["iproute"] / "bin" / "ip").string());
      std::stringstream cmd;
      cmd << iproute << " link add " << in_if_name << " type veth peer name " << out_if_name;
      int err = system(cmd.str().c_str());
      if ( err != 0 ) {
        BOOST_LOG_TRIVIAL(error) << "Could not run " << cmd.str() << ": " << err;
        return -err;
      }

      cmd.str("");
      cmd << iproute << " link set " << in_if_name << " master bridge";
      err = system(cmd.str().c_str());
      if ( err != 0 ) {
        BOOST_LOG_TRIVIAL(error) << "Could not run " << cmd.str() << ": " << err;
        return -err;
      }

      cmd.str("");
      cmd << iproute << " link set " << in_if_name << " up";
      err = system(cmd.str().c_str());
      if ( err != 0 ) {
        BOOST_LOG_TRIVIAL(error) << "Could not run " << cmd.str() << ": " << err;
        return -err;
      }

      return 1;
    }

    int BridgeController::move_if_to_ns(const std::string &if_name,
                                        int netns_fd) {
      int nl_socket(socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE));
      if ( nl_socket == -1 )
        return -errno;

      // Get device index
      struct ifreq ifr;
      *std::copy(if_name.begin(), if_name.end(), ifr.ifr_name) = '\0';
      if ( ioctl(nl_socket, SIOCGIFINDEX, &ifr, sizeof(ifr)) == -1 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "move_if_to_ns: Could not get " << if_name << " index: " << ec;
        return -ec;
      }

      BOOST_LOG_TRIVIAL(debug) << "Interface index for " << if_name << " is " << ifr.ifr_ifindex;

      struct {
        struct nlmsghdr nl;
        struct ifinfomsg ifi;
        struct rtattr ns_fd_a;
        int ns_fd;
      } nl_msg;

      nl_msg.nl.nlmsg_len = sizeof(nl_msg);
      nl_msg.nl.nlmsg_type = RTM_SETLINK;
      nl_msg.nl.nlmsg_flags = NLM_F_ACK | NLM_F_REQUEST;
      nl_msg.nl.nlmsg_seq = 0;
      nl_msg.nl.nlmsg_pid = getpid();
      nl_msg.ifi.ifi_family = AF_UNSPEC;
      nl_msg.ifi.ifi_type = ARPHRD_ETHER;
      nl_msg.ifi.ifi_index = ifr.ifr_ifindex;
      nl_msg.ifi.ifi_flags = 0;
      nl_msg.ifi.ifi_change = 0xFFFFFFFF;
      nl_msg.ns_fd_a.rta_type = IFLA_NET_NS_FD;
      nl_msg.ns_fd_a.rta_len = RTA_LENGTH(sizeof(int));
      nl_msg.ns_fd = netns_fd;
      BOOST_LOG_TRIVIAL(debug) << "Net namespace fds " << netns_fd << " != " << m_netns_fd;

      int err;
      err = setregid(0, 0);
      if ( err < 0 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "move_if_to_ns: could not set group: " << ec;
        return -ec;
      }

      err = send(nl_socket, (void *)&nl_msg, sizeof(nl_msg), 0);
      if ( err < 0 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "move_if_to_ns: could not send Netlink message: " << ec;
        return -ec;
      }

      char recv_buf[1024];
      err = recv(nl_socket, recv_buf, sizeof(recv_buf), 0);
      if ( err < 0 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "move_if_to_ns: could not receive Netlink message: " << ec;
        return -ec;
      }

      struct nlmsghdr *resp((struct nlmsghdr *)recv_buf);
      if ( resp->nlmsg_type != NLMSG_ERROR ) {
        BOOST_LOG_TRIVIAL(error) << "move_if_to_ns: did not get ack from kernel: " << resp->nlmsg_type;
        return -EINVAL;
      }

      if ( resp->nlmsg_len < sizeof(*resp) + sizeof(nlmsgerr) ) {
        BOOST_LOG_TRIVIAL(error) << "move_if_to_ns: not enough data in netlink response: " << resp->nlmsg_len;
        return -EINVAL;
      }

      struct nlmsgerr *nl_err((struct nlmsgerr *)NLMSG_DATA(resp));
      if ( nl_err->error != 0 ) {
        BOOST_LOG_TRIVIAL(error) << "move_if_to_ns: could not set namespace: " << nl_err->error;
        return -nl_err->error;
      }

      BOOST_LOG_TRIVIAL(info) << "Moved " << if_name << " to " << netns_fd;
      system("ifconfig -a");

      close(nl_socket);

      return 1;
    }

    std::array<std::uint8_t, ETH_ALEN> BridgeController::lookup_arp(const boost::asio::ip::address_v4 &ip,
                                                                    bool &was_found) {
      boost::unique_lock l(m_arp_mutex);

      BOOST_LOG_TRIVIAL(debug)<< "Lookup arp " << ip << "(" << ip.to_ulong() << ")";
      auto found(m_arp_table.find(ip.to_ulong()));
      if ( found == m_arp_table.end() ) {
        was_found = false;
        return std::array<std::uint8_t, ETH_ALEN>();
      } else {
        was_found = true;
        return found->second;
      }
    }

    void BridgeController::add_arp_entry(const boost::asio::ip::address_v4 &addr,
                                         const std::array<std::uint8_t, ETH_ALEN> &hw_addr) {
      boost::unique_lock l(m_arp_mutex);
      m_arp_table[addr.to_ulong()] = hw_addr;

      BOOST_LOG_TRIVIAL(debug) << "Add arp entry " << addr << "(" << addr.to_ulong() << ") -> " << boost::log::dump(hw_addr.data(), ETH_ALEN);
    }

    void BridgeController::read_tap(std::size_t mtu) {
      m_tap_buf.resize(mtu);
      m_tap_stream.async_read_some(boost::asio::buffer(m_tap_buf),
                                   boost::bind(&BridgeController::on_packet_read, this,
                                               boost::asio::placeholders::error,
                                               boost::asio::placeholders::bytes_transferred));
    }

    void BridgeController::on_packet_read(boost::system::error_code ec, std::size_t bytes_read) {
      if ( ec ) {
        BOOST_LOG_TRIVIAL(error) << "Could not read tap device: " << ec;
      } else {
        // Do something with this packet
        std::uintptr_t raw_buf((std::uintptr_t) m_tap_buf.data());

        log_incoming_pkt((void *) raw_buf, bytes_read);

        EthPacket<char> *pkt((EthPacket<char> *)raw_buf);
        std::uint16_t ether_type(ntohs(pkt->hdr.ether_type));

        switch ( ether_type ) {
        case ETHERTYPE_ARP:
          handle_arp((void *) raw_buf, bytes_read);
          break;
        case ETHERTYPE_IP:
          handle_ip((void *) raw_buf, bytes_read);
          break;
        case ETHERTYPE_IPV6:
          break;
        default:
          BOOST_LOG_TRIVIAL(debug) << "Dropping packet of type " << ether_type;
          break;
        }

        read_tap(m_tap_buf.size());
      }
    }

    void BridgeController::handle_ip(void *buf, std::size_t sz) {
      if ( sz < sizeof(IpPacket) ) return;
      IpPacket *pkt((IpPacket *) buf);

      if ( std::equal(m_stork_mac.begin(), m_stork_mac.end(), pkt->hdr.ether_dhost) &&
           ntohl(pkt->pkt.daddr) == m_bridge_addr.to_ulong() ) {
        BOOST_LOG_TRIVIAL(debug) << "Receive IP packet to stork daemon";

        switch ( pkt->pkt.protocol ) {
        case IPPROTO_ICMP: {
          BOOST_LOG_TRIVIAL(debug) << "Intercepted IP ICMP request";
          struct icmphdr *icmp(pkt->after<struct icmphdr*>());
          switch ( icmp->type ) {
          case ICMP_ECHO: {
            std::size_t echo_bytes(ntohs(pkt->pkt.tot_len) - (pkt->pkt.ihl * 4) - sizeof(struct icmphdr));
            BOOST_LOG_TRIVIAL(debug) << "Receive ping request with " << echo_bytes << " of extra data";

            bool arp_found(false);
            auto d_hw_addr(lookup_arp(boost::asio::ip::address_v4(ntohl(pkt->pkt.saddr)), arp_found));
            if ( !arp_found )
              BOOST_LOG_TRIVIAL(debug) << "Could not ARP " << boost::asio::ip::address_v4(ntohl(pkt->pkt.saddr));

            if ( arp_found && echo_bytes < 1024 ) {
              std::size_t response_sz(sizeof(EthPacket<IcmpEchoReply>) + echo_bytes);
              response_sz = 2 * ((response_sz + 1) / 2);

              char reply_buf[response_sz];
              auto reply((EthPacket<IcmpEchoReply> *) reply_buf);
              std::copy(d_hw_addr.begin(), d_hw_addr.end(), reply->hdr.ether_dhost);
              std::copy(m_stork_mac.begin(), m_stork_mac.end(), reply->hdr.ether_shost);
              reply->hdr.ether_type = htons(ETHERTYPE_IP);
              reply->pkt.ip.version = 4;
              reply->pkt.ip.ihl = 5;
              reply->pkt.ip.tos = 0x00;
              reply->pkt.ip.tot_len = htons(response_sz - sizeof(reply->hdr));
              reply->pkt.ip.id = pkt->pkt.id;
              reply->pkt.ip.frag_off = htons(IP_DF);
              reply->pkt.ip.ttl = 64;
              reply->pkt.ip.protocol = IPPROTO_ICMP;
              reply->pkt.ip.check = 0;
              reply->pkt.ip.saddr = ntohl(m_bridge_addr.to_ulong());
              reply->pkt.ip.daddr = pkt->pkt.saddr;
              reply->pkt.icmp.type = ICMP_ECHOREPLY;
              reply->pkt.icmp.code = 0;
              reply->pkt.icmp.checksum = 0;
              reply->pkt.icmp.un.echo.id = icmp->un.echo.id;
              reply->pkt.icmp.un.echo.sequence = icmp->un.echo.sequence;
              std::copy(pkt->after<char *>(sizeof(struct icmphdr)),
                        pkt->after<char *>(sizeof(struct icmphdr) + echo_bytes),
                        reply->after<char *>());

              reply->pkt.ip.check = htons(calc_ip_checksum(&reply->pkt.ip));
              reply->pkt.icmp.checksum = htons(calc_ip_checksum((std::uint16_t *) &reply->pkt.icmp,
                                                                (response_sz - sizeof(reply->hdr) - sizeof(reply->pkt.ip)) / 2));

              write_raw_tap_pkt(reply_buf, response_sz);
            }

            break;
          }
          case ICMP_ECHOREPLY:
            // Nothing to be done on PING reply
            break;
          default:
            BOOST_LOG_TRIVIAL(debug) << "Received ICMP request of type: " << (int)icmp->type;
            break;
          }
          break;
        }
        case IPPROTO_UDP: {
          struct udphdr *udp(pkt->after<struct udphdr*>());
          boost::asio::ip::address_v4 saddr(ntohl(pkt->pkt.saddr));
          std::uint16_t sport(ntohs(udp->source)),
            dport(ntohs(udp->dest));
          const void *raw_data(pkt->after<const void *>(sizeof(*udp)));
          std::uint16_t raw_data_len(ntohs(udp->len) - sizeof(*udp));

          if ( dport == STORKD_INTERNAL_UDP_PORT ) {
            // TODO make this more robust
            BOOST_LOG_TRIVIAL(debug) << "Received UDP packet that we will handle: "
                                     << boost::log::dump(raw_data, raw_data_len);

            std::uint32_t app_uri_len(ntohl(*((std::uint32_t *) raw_data)));
            char *app_uri_ptr((char *) (((std::uintptr_t)raw_data) + 4));
            if ( (app_uri_len + 4) < raw_data_len ) {
              // For now, this should contain a string representing the
              // application this container wants to open
              //
              // We know who the container is by both its IP address as
              // well as the capability sent to us
              std::string capability(app_uri_ptr + app_uri_len, raw_data_len - (app_uri_len + 4));
              BOOST_LOG_TRIVIAL(debug) << "The capability is " << capability;

              // First check if the IP address belongs to any known container
              backend::PersonaId pid;
              AppInstanceId app_instance_id;
              if ( m_container_mgr.persona_id_from_ip(saddr, pid) ) {
                // Check the capability
                if ( capability == persona_capability(pid) ) {
                  // Send back a UDP datagram that contains the address
                  auto resolver(std::make_shared<AppInstanceForPersonaResolver>
                                (*this, m_container_mgr, m_backend,
                                 saddr, sport, pid, std::string(app_uri_ptr, app_uri_len)));
                  resolver->async_resolve();
                } else {
                  auto exp(persona_capability(pid));
                  BOOST_LOG_TRIVIAL(debug) << "Rejecting open request because of permissions failure: expected " << exp;
                  BOOST_LOG_TRIVIAL(debug) << capability.size() << " != " << exp.size();
                  BOOST_LOG_TRIVIAL(debug) << capability << " == " << exp << ": " << (capability == exp ? "true" : "false");
                }
              } else if ( m_container_mgr.app_instance_id_from_ip(saddr, app_instance_id) ) {
                pid = app_instance_id.persona_id();
                if ( capability == app_instance_capability(pid, app_instance_id.app_id()) ) {
                  BOOST_LOG_TRIVIAL(debug) << "TODO: resolve app instance permissions to open other applications";
                } else
                  BOOST_LOG_TRIVIAL(debug) << "Rejecting open request because of permissions failure";
              } else
                BOOST_LOG_TRIVIAL(debug) << "Rejecting open request because we don't know who sent this";
            }
          } else {
            auto listener(find_udp_listener(dport));
            if ( listener ) {
              listener->on_udp_packet
                (saddr, sport, dport,
                 boost::asio::buffer(raw_data, raw_data_len));
            }
          }

          break;
        }
        default:
          BOOST_LOG_TRIVIAL(debug) << "Unknown IP protocol: " << (int)pkt->pkt.protocol;
          break;
        }
      }
    }

    void BridgeController::handle_arp(void *arp_buf, std::size_t arp_buf_sz) {
      if ( arp_buf_sz < sizeof(ArpPacket) )
        return;

      ArpPacket *pkt((ArpPacket *) arp_buf);

      std::uint16_t hrd(ntohs(pkt->pkt.ar_hrd));
      if ( hrd != ARPHRD_ETHER ) {
        BOOST_LOG_TRIVIAL(error) << "Dropping ARP packet of type " << hrd;
        return;
      }

      std::uint16_t ether_type(ntohs(pkt->pkt.ar_pro));
      if ( ether_type != ETHERTYPE_IP && ether_type != ETHERTYPE_IPV6) {
        BOOST_LOG_TRIVIAL(error) << "Dropping ARP packet for protocol " << ether_type;
        return;
      }

      if ( pkt->pkt.ar_hln != ETH_ALEN ||
           (ether_type == ETHERTYPE_IP &&  pkt->pkt.ar_pln != 4) ||
           (ether_type == ETHERTYPE_IPV6 && pkt->pkt.ar_pln != 16) ) {
        BOOST_LOG_TRIVIAL(error) << "Dropping ARP protocol because addr length mismatch: " << (int) pkt->pkt.ar_hln << " " << (int) pkt->pkt.ar_pln;
        return;
      }

      switch ( ntohs(pkt->pkt.ar_op) ) {
      case ARPOP_REQUEST:
        if ( ether_type == ETHERTYPE_IP ) {
          boost::asio::ip::address_v4 a(ntohl(*(pkt->after<std::uint32_t *>(2 * ETH_ALEN + pkt->pkt.ar_pln))));
          bool was_found(false);
          EthPacket<ArpIPV4Response> rsp;

          std::fill(rsp.hdr.ether_dhost, rsp.hdr.ether_dhost + ETH_ALEN, 0xFF);
          rsp.hdr.ether_type = htons(ETHERTYPE_ARP);
          rsp.pkt.hdr.ar_hrd = htons(ARPHRD_ETHER);
          rsp.pkt.hdr.ar_pro = htons(ETHERTYPE_IP);
          rsp.pkt.hdr.ar_hln = ETH_ALEN;
          rsp.pkt.hdr.ar_pln = 4;
          rsp.pkt.hdr.ar_op = htons(ARPOP_REPLY);
          rsp.pkt.tgt_hw_ip = *(pkt->after<uint32_t *>(pkt->pkt.ar_hln)); // htonl(m_bridge_addr.to_ulong());
          std::fill(rsp.pkt.tgt_hw_addr, rsp.pkt.tgt_hw_addr+ ETH_ALEN, 0xFF);

          if ( a == m_bridge_addr ) {
            // Respond with our MAC address
            BOOST_LOG_TRIVIAL(info) << "Responding with our mac " << boost::log::dump(m_stork_mac.data(), ETH_ALEN);

            was_found = true;
            std::copy(m_stork_mac.begin(), m_stork_mac.end(), rsp.hdr.ether_shost);
            std::copy(m_stork_mac.begin(), m_stork_mac.end(), rsp.pkt.src_hw_addr);
            rsp.pkt.src_hw_ip = htonl(m_bridge_addr.to_ulong());

          } else {
            // TODO can i make linux do this?
            BOOST_LOG_TRIVIAL(info) << "Ignoring arp request for " << a;
            auto hw_addr(lookup_arp(a, was_found));
            if ( was_found ) {
              std::copy(hw_addr.begin(), hw_addr.end(), rsp.hdr.ether_shost);
              std::copy(hw_addr.begin(), hw_addr.end(), rsp.pkt.src_hw_addr);
              rsp.pkt.src_hw_ip = htonl(a.to_ulong());
            }
          }

          if ( was_found )
            write_tap_pkt(rsp);
        }
        break;
      case ARPOP_REPLY:
        return;
      default:
        BOOST_LOG_TRIVIAL(debug) << "Dropping ARP packet with unknown op: " << ntohs(pkt->pkt.ar_op);
        return;
      }
    }

    void BridgeController::write_raw_tap_pkt(void *buf, std::size_t sz) {
      log_outgoing_pkt(buf, sz);

      int err = write(m_tap_stream.native_handle(), buf, sz);
      if ( err == -1 ) {
        if ( errno == EAGAIN || errno == EWOULDBLOCK ) {
          BOOST_LOG_TRIVIAL(error) << "Raw TAP packet writing will block";
          return;
        } else {
          auto ec(errno);
          BOOST_LOG_TRIVIAL(error) << "Could not write raw TAP packet: " << ec;
          return;
        }
      }

      assert(err == ((int) sz));
    }

    void BridgeController::log_outgoing_pkt(void *buf, std::size_t sz) {
      boost::upgrade_lock l(m_dbg_mutex);
      if ( m_eth_debug.is_open() ) {
        boost::upgrade_to_unique_lock l_unique(l);

        std::cerr << "log outgoing" << std::endl;
        auto cur_time(boost::posix_time::microsec_clock::local_time().time_of_day());
        m_eth_debug << "O " << cur_time << " 0000 " << boost::log::dump(buf, sz) << std::endl;
        m_eth_debug.flush();
      }
    }

    void BridgeController::log_incoming_pkt(void *buf, std::size_t sz) {
      boost::upgrade_lock l(m_dbg_mutex);
      if ( m_eth_debug.is_open() ) {
        boost::upgrade_to_unique_lock l_unique(l);

        auto cur_time(boost::posix_time::microsec_clock::local_time().time_of_day());
        m_eth_debug << "I " << cur_time << " 0000 " << boost::log::dump(buf, sz) << std::endl;
        m_eth_debug.flush();
      }
    }

    BridgeController::Capability BridgeController::persona_capability(const backend::PersonaId &pid) {
      std::stringstream cap;
      cap << "P/" << pid.id() << "/";

      std::string ret(cap.str());
      sign_capability(ret);
      return ret;
    }

    BridgeController::Capability BridgeController::app_instance_capability(const backend::PersonaId &pid,
                                                                           const application::ApplicationIdentifier &app_id) {
      std::stringstream cap;
      cap << "A/" << pid.id() << "/" << app_id.app_id() << "/" << app_id.domain() << "/";

      std::string ret(cap.str());
      sign_capability(ret);
      return ret;
    }

    void BridgeController::sign_capability(std::string &cap) {
      std::shared_ptr<HMAC_CTX> ctx(HMAC_CTX_new(), HMAC_CTX_free);
      if ( !ctx ) return;

      if ( !HMAC_Init_ex(ctx.get(), m_cap_key.c_str(), m_cap_key.size(),
                         EVP_sha256(), NULL) ) return;

      if ( !HMAC_Update(ctx.get(), (unsigned char *) cap.c_str(), cap.size()) ) return;

      unsigned char hash[32];
      unsigned int len(sizeof(hash));
      if ( !HMAC_Final(ctx.get(), hash, &len) ) return;
      assert(len == sizeof(hash));

      std::stringstream out;
      util::dump_hex(out, hash);

      cap += out.str();
    }

    BridgeController::UsedUdpPort BridgeController::use_udp_port(std::uint16_t port) {
      boost::unique_lock l(m_udp_mutex);
      boost::random::random_device rng;
      boost::random::uniform_int_distribution<std::uint16_t> port_gen(49152, 65535);

      for ( int tries = 0; tries < 100; ++tries ) {
        std::uint16_t port_to_allocate(port);
        if ( port_to_allocate == 0 )
          port_to_allocate = port_gen(rng);

        if ( m_udp_ports.find(port_to_allocate) == m_udp_ports.end() ) {
          m_udp_ports[port_to_allocate] = nullptr;
          return UsedUdpPort(*this, port_to_allocate);
        }
      }

      return UsedUdpPort(*this, 0);
    }

    void BridgeController::release_udp(std::uint16_t port) {
      boost::unique_lock l(m_udp_mutex);
      auto found(m_udp_ports.find(port));
      if ( found == m_udp_ports.end() ) return;

      m_udp_ports.erase(found);
    }

    void BridgeController::set_udp_listener(std::uint16_t port, IUdpListener *l) {
      boost::unique_lock udp_l(m_udp_mutex);
      auto found(m_udp_ports.find(port));
      if ( found == m_udp_ports.end() ) return;

      found->second = l;
    }

    IUdpListener *BridgeController::find_udp_listener(std::uint16_t port) {
      boost::shared_lock udp_l(m_udp_mutex);
      auto found(m_udp_ports.find(port));
      if ( found == m_udp_ports.end() ) return nullptr;
      else return found->second;
    }

    void BridgeController::write_udp_packet(std::uint16_t sport, std::uint16_t dport,
                                            const boost::asio::ip::address_v4 &a_dst,
                                            const boost::asio::const_buffer &b) {
      bool hw_addr_found(false);
      auto hw_addr(lookup_arp(a_dst, hw_addr_found));

      if ( !hw_addr_found ) return;
      if ( boost::asio::buffer_size(b) > 2048 ) return;

      EthPacket<UdpPacket> *pkthdr;
      std::size_t buf_sz(boost::asio::buffer_size(b) + sizeof(*pkthdr));
      char buf[buf_sz];
      pkthdr = (EthPacket<UdpPacket> *) buf;

      std::copy(hw_addr.begin(), hw_addr.end(), pkthdr->hdr.ether_dhost);
      std::copy(m_stork_mac.begin(), m_stork_mac.end(), pkthdr->hdr.ether_shost);
      pkthdr->hdr.ether_type = htons(ETHERTYPE_IP);
      pkthdr->pkt.ip.version = 4;
      pkthdr->pkt.ip.ihl = 5;
      pkthdr->pkt.ip.tos = 0;
      pkthdr->pkt.ip.tot_len = htons(buf_sz - sizeof(pkthdr->hdr));
      pkthdr->pkt.ip.id = 0xBEEF;
      pkthdr->pkt.ip.frag_off = htons(IP_DF);
      pkthdr->pkt.ip.ttl = 64;
      pkthdr->pkt.ip.protocol = IPPROTO_UDP;
      pkthdr->pkt.ip.check = 0;
      pkthdr->pkt.ip.saddr = htonl(m_bridge_addr.to_ulong());
      pkthdr->pkt.ip.daddr = htonl(a_dst.to_ulong());
      pkthdr->pkt.udp.uh_sport = htons(sport);
      pkthdr->pkt.udp.uh_dport = htons(dport);
      pkthdr->pkt.udp.uh_ulen = htons(boost::asio::buffer_size(b) + sizeof(pkthdr->pkt.udp));
      pkthdr->pkt.udp.uh_sum = 0;

      pkthdr->pkt.ip.check = htons(calc_ip_checksum(&pkthdr->pkt.ip));

      const std::uint8_t *udp_buf(boost::asio::buffer_cast<const std::uint8_t *>(b));
      std::copy(udp_buf, udp_buf + boost::asio::buffer_size(b), pkthdr->after<std::uint8_t *>());

      write_raw_tap_pkt(buf, buf_sz);
    }

    // UsedUdpPort
    BridgeController::UsedUdpPort::UsedUdpPort(UsedUdpPort &&p)
      : m_controller(p.m_controller),
        m_port(p.m_port) {
      p.m_port = 0;
    }

    BridgeController::UsedUdpPort::UsedUdpPort(BridgeController &c)
      : m_controller(c), m_port(0) {
    }

    BridgeController::UsedUdpPort::UsedUdpPort(BridgeController &c, std::uint16_t p)
      : m_controller(c), m_port(p) {
    }

    BridgeController::UsedUdpPort::~UsedUdpPort() {
      if ( m_port != 0 )
        m_controller.release_udp(m_port);
    }

    void BridgeController::UsedUdpPort::listen(IUdpListener *l) {
      m_controller.set_udp_listener(m_port, l);
    }

    void BridgeController::UsedUdpPort::write_pkt(const boost::asio::ip::address_v4 &a_dst, std::uint16_t p_dst, const boost::asio::const_buffer &b) {
      m_controller.write_udp_packet(m_port, p_dst, a_dst, b);
    }
  }
}
