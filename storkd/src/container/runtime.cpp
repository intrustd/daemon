#include <boost/log/trivial.hpp>
#include <sstream>

#include <asm/types.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

#include <linux/if_tun.h>
#include <linux/rtnetlink.h>

#include "runtime.hpp"

namespace fs = boost::filesystem;

// This is a test do not use
void test_tunalloc() {
  static const char *clone_dev = "/dev/net/tun";

  int fd = open(clone_dev, O_RDWR);
  if ( fd < 0 ) {
    auto err(errno);
    BOOST_LOG_TRIVIAL(error) << "Error opening TUN clone device: " << err;
    return;
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = IFF_TUN;

  int err = ioctl(fd, TUNSETIFF, (void *) &ifr);
  if ( err < 0 ) {
    auto err(errno);
    close(fd);
    BOOST_LOG_TRIVIAL(error) << "Error creating TUN device: " << err;
    return;
  }

  char device_name[sizeof(ifr.ifr_name)];
  strncpy(device_name, ifr.ifr_name, sizeof(device_name));

  BOOST_LOG_TRIVIAL(info) << "Made TUN device: " << device_name;
//  close(fd);
}

namespace stork {
  namespace container {
    int ns_trampoline(void *d) {
      static_cast<NamespacesInitializer *>(d)->do_setup();
      exit(EXIT_SUCCESS);
      return 0;
    }

    NamespacesInitializer::NamespacesInitializer(std::size_t stack_sz)
      : m_is_setting_up(false), m_stack(stack_sz) {
    }

    NamespacesInitializer::~NamespacesInitializer() {
    }

    void NamespacesInitializer::async_setup_namespaces(std::function<void(std::error_code, pid_t, int)> cb) {
      if ( !m_is_setting_up.exchange(true) ) {
        // Now we can start the setup
        int error = socketpair(AF_UNIX, SOCK_DGRAM, 0, m_ipc_sockets);
        if ( error < 0 ) {
          cb(std::error_code(errno, std::generic_category()), 0, -1);
          BOOST_LOG_TRIVIAL(error) << "Error creating socket pair";
        }

        int clone_flags =
          CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET |
          CLONE_NEWNS     | CLONE_NEWPID | CLONE_NEWUSER |
          CLONE_NEWUTS    | CLONE_PARENT | SIGCHLD ;

        BOOST_LOG_TRIVIAL(info) << "Parent pid " << getpid();
        int child_id = clone(ns_trampoline, m_stack.data() + m_stack.size(), clone_flags, (void *) this);
        if ( child_id < 0 ) {
          int error = errno;

          close(m_ipc_sockets[0]);
          close(m_ipc_sockets[1]);
          BOOST_LOG_TRIVIAL(error) << "Error cloning: " << error;
          cb(std::make_error_code(namespace_system_error), 0, -1);
        } else {
          close(m_ipc_sockets[1]);

          NamespaceInitializationData ni_data;
          ni_data.abs_pid = child_id;
          ni_data.root_uid = getuid();
          ni_data.root_gid = getgid();

          send(m_ipc_sockets[0], &ni_data, sizeof(ni_data), 0);

          BOOST_LOG_TRIVIAL(info) << "Got child pid: " << child_id;
          cb(std::error_code(), child_id, m_ipc_sockets[0]);
        }
      } else
        cb(std::make_error_code(namespace_already_initializing), 0, -1);
    }

    void NamespacesInitializer::do_setup() {
      NamespaceInitializationData ni_data;

      BOOST_LOG_TRIVIAL(info) << "do_setup: " << getpid();

      close(m_ipc_sockets[0]);

      int e = recv(m_ipc_sockets[1], &ni_data, sizeof(ni_data), 0);
      if ( e != sizeof(ni_data) ) {
        BOOST_LOG_TRIVIAL(error) << "Could not read external PID";
        exit(EXIT_FAILURE);
      }
      BOOST_LOG_TRIVIAL(info) << "Got our external PID: " << ni_data.abs_pid;

      std::stringstream proc_path;
      proc_path << "/proc/" << ni_data.abs_pid;
      fs::path proc(proc_path.str());

      Namespaces nss(ni_data, proc);
      setup(nss, m_ipc_sockets[1]);

//      // TODO we should also map in an unprivileged uid and gid
//      std::stringstream uid_map;
//      uid_map << 0 << " " << ni_data.root_uid << " " << 1 << std::endl;
//
//      auto uid_map_path(proc);
//      uid_map_path /= "uid_map";
//      std::fstream uid_map_file(uid_map_path.string(), std::fstream::out);
//      uid_map_file << uid_map.str();
//      uid_map_file.close();
//
//      uid_map.str("");
//      uid_map << 0 << " " << ni_data.root_gid << " " << 1 << std::endl;
//
//      auto gid_map_path(proc);
//      gid_map_path /= "gid_map";
//      std::fstream gid_map_file(gid_map_path.string(), std::fstream::out);
//      gid_map_file << uid_map.str();
//      gid_map_file.close();
//
//      int err = setreuid(0, 0);
//      if ( err < 0 ) {
//        auto ec(std::error_code(errno, std::generic_category()));
//        BOOST_LOG_TRIVIAL(error) << "setreuid: " << ec;
//      }
//      setregid(0, 0);
//
//      uid_t uid = getuid();
//      BOOST_LOG_TRIVIAL(debug) << "User id is " << uid;
//
//      // Attempt to make tun device
//      test_tunalloc();
//
//      // Attempt to run ifconfig
//      BOOST_LOG_TRIVIAL(info) << "Running ifconfig";
//      err = execl("/nix/store/vjpmcdqffck64cmvj5dkazkg4drs3a3a-net-tools-1.60_p20170221182432/bin/ifconfig", "ifconfig", "tun0", (char *) 0);
//      BOOST_LOG_TRIVIAL(info) << "Running ifconfig:" << err;
    }

    void NamespacesInitializer::setup(Namespaces &ns, int comm) {
    }

    // TunDevice

    TunDevice::TunDevice(TunDevice &&d)
      : NetworkDevice(std::move(d)),
        m_tun_fd(d.m_tun_fd) {
      d.m_tun_fd = -1;
    }

    TunDevice::TunDevice()
      : m_tun_fd(-1) {
      open();
    }

    TunDevice::~TunDevice() {
      if ( m_tun_fd > 0 )
        close(m_tun_fd);
    }

    int TunDevice::steal() {
      auto ret(m_tun_fd);
      m_tun_fd = -1;
      m_device_name.clear();
      return ret;
    }

    void TunDevice::open() {
      static const char *clone_dev = "/dev/net/tun";

      int fd = ::open(clone_dev, O_RDWR);
      if ( fd < 0 ) {
        auto err(errno);
        BOOST_LOG_TRIVIAL(error) << "Error opening TUN clone device: " << err;
        return;
      }

      struct ifreq ifr;
      memset(&ifr, 0, sizeof(ifr));

      ifr.ifr_flags = IFF_TUN;

      int err = ioctl(fd, TUNSETIFF, (void *) &ifr);
      if ( err < 0 ) {
        auto err(errno);
        close(fd);
        BOOST_LOG_TRIVIAL(error) << "Error creating TUN device: " << err;
        return;
      }

      device_name(std::string(ifr.ifr_name, strlen(ifr.ifr_name)));
      m_tun_fd = fd;
    }

    // NetworkConfigurator

    NetworkConfigurator::NetworkConfigurator()
      : m_conf_fd(-1), m_msg_seq(0) {
      open();
    }

    NetworkConfigurator::~NetworkConfigurator() {
      BOOST_LOG_TRIVIAL(debug) << "Destroying network configurator";
      if ( m_conf_fd > 0 ) close(m_conf_fd);
    }

    void NetworkConfigurator::open() {
      int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
      if ( fd < 0 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Error opening netlink socket: " << ec;
      }

      m_conf_fd = fd;
    }

    IfaceConfigurator NetworkConfigurator::operator() (const NetworkDevice &d) {
      return IfaceConfigurator(*this, d);
    }

    void NetworkConfigurator::send_request(nlmsghdr *n) {
      n->nlmsg_seq = m_msg_seq ++;
      n->nlmsg_pid = getpid();

      struct sockaddr_nl addr_nl;
      addr_nl.nl_family = AF_NETLINK;
      addr_nl.nl_pid = 0;
      addr_nl.nl_groups = 0;

      struct iovec iov[] = {
        { .iov_base = (void *) n,
          .iov_len = n->nlmsg_len }
      };

      struct msghdr msg;
      msg.msg_name = (char *) &addr_nl;
      msg.msg_namelen = sizeof(addr_nl);

      msg.msg_iov = iov;
      msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);

      msg.msg_control = NULL;
      msg.msg_controllen = 0;

      msg.msg_flags = 0;

      if ( sendmsg(m_conf_fd, &msg, 0) < 0 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not send netlink message: " << ec;
      }
    }

    int NetworkConfigurator::recv_ack() const {
      struct {
        nlmsghdr n;
        nlmsgerr e;
      } resp;

      struct sockaddr_nl addr_nl;
      struct iovec iov[] = {
        { .iov_base = (void *) &resp,
          .iov_len = sizeof(resp) }
      };
      struct msghdr msg;
      msg.msg_name = (char *) &addr_nl;
      msg.msg_namelen = sizeof(addr_nl);

      msg.msg_iov = iov;
      msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);

      msg.msg_control = NULL;
      msg.msg_controllen = 0;

      msg.msg_flags = 0;

      auto res(recvmsg(m_conf_fd, &msg, 0));
      if ( res < 0 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not receive netlink message: " << ec;
        return -1;
      }

      BOOST_LOG_TRIVIAL(debug) << "Received " << res << " bytes over netlink socket";

      if ( resp.n.nlmsg_type == NLMSG_ERROR ) {
        return resp.e.error;
      } else {
        BOOST_LOG_TRIVIAL(debug) << "Received unknown response message: " << resp.n.nlmsg_type
                                 << ", expected " << NLMSG_ERROR;
        return -1;
      }
    }

    IfaceConfigurator::IfaceConfigurator(NetworkConfigurator &net, const NetworkDevice &d)
      : m_net(net), m_device(d) {
      open();
    }

    void IfaceConfigurator::open() {
      ifreq ifr;
      set_ifr_name(ifr);

      if ( ioctl(m_net.m_conf_fd, SIOCGIFINDEX, (void *)&ifr) < 0 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not get interface index for " << m_device.device_name()
                                 << ": " << ec;
      }

      m_if_index = ifr.ifr_ifindex;
    }

    void IfaceConfigurator::set_ifr_name(ifreq &ifr) {
      const std::string &if_name(m_device.device_name());
      std::size_t if_name_length(std::min(if_name.size(), sizeof(ifr.ifr_name) - 1));
      std::copy_n(if_name.begin(), if_name_length, ifr.ifr_name);
      ifr.ifr_name[if_name_length] = 0;
    }

    IfaceConfigurator &IfaceConfigurator::add_address(const boost::asio::ip::address_v6 &v6,
                                                      std::uint8_t prefix_len) {
      if ( m_net.is_valid() ) {
        struct {
          nlmsghdr n;
          ifaddrmsg addr;

          struct {
            rtattr a;
            in6_addr d;
          } local_attr;
        } msg;

        msg.n.nlmsg_len = sizeof(msg);
        msg.n.nlmsg_type = RTM_NEWADDR;
        msg.n.nlmsg_flags = NLM_F_EXCL | NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK;

        msg.addr.ifa_family = AF_INET6;
        msg.addr.ifa_prefixlen = prefix_len;
        msg.addr.ifa_flags = IFA_F_PERMANENT;
        msg.addr.ifa_scope = RT_SCOPE_LINK; // Local
        msg.addr.ifa_index = m_if_index;

        msg.local_attr.a.rta_len = sizeof(msg.local_attr);
        msg.local_attr.a.rta_type = IFA_LOCAL;

        auto raw_v6(v6.to_bytes());
        std::copy(raw_v6.begin(), raw_v6.end(),
                  msg.local_attr.d.s6_addr);

        m_net.send_request((nlmsghdr *) &msg);
        int err = m_net.recv_ack();
        if ( err == 0 )
          BOOST_LOG_TRIVIAL(debug) << "Added address";
        else
          BOOST_LOG_TRIVIAL(error) << "Could not add IPv6 address: " << err;
      } else
        BOOST_LOG_TRIVIAL(error) << "IfaceConfigurator::add_address: skipping on invalid network";
      return *this;
    }

    IfaceConfigurator &IfaceConfigurator::bring_up() {
      if ( m_net.is_valid() ) {
        struct ifreq ifr;
        set_ifr_name(ifr);
        ifr.ifr_flags = IFF_UP | IFF_RUNNING;

        if ( ioctl(m_net.m_conf_fd, SIOCSIFFLAGS, (void *) &ifr) < 0 ) {
          auto ec(errno);
          BOOST_LOG_TRIVIAL(error) << "Could not bring up network device " << m_device.device_name()
                                   << ": " << ec;
        } else
          BOOST_LOG_TRIVIAL(debug) << "Brought up network device " << m_device.device_name();
      } else
        BOOST_LOG_TRIVIAL(error) << "IfaceConfigurator::bring_up: skipping on invalid network";
      return *this;
    }

    // Namespaces

    Namespaces::Namespaces(const NamespaceInitializationData &ni_data,
                           const fs::path &proc_path)
      : m_init_data(ni_data) {

      // TODO we should open these after we have the uid set
      // auto ns_path(proc_path);
      // ns_path /= "ns";

      // auto cgroup_path(ns_path), ipc_path(ns_path), network_path(ns_path),
      //   mount_path(ns_path), pid_path(ns_path), user_path(ns_path),
      //   uts_path(ns_path);

      // cgroup_path /= "cgroup";
      // ipc_path /= "ipc";
      // network_path /= "net";
      // mount_path /= "mnt";
      // pid_path /= "pid";
      // user_path /= "user";
      // uts_path /= "uts";

      // m_cgroup_fd = open_ns(cgroup_path);
      // m_ipc_fd = open_ns(ipc_path);
      // m_network_fd = open_ns(network_path);
      // m_mount_fd = open_ns(mount_path);
      // m_pid_fd = open_ns(pid_path);
      // m_user_fd = open_ns(user_path);
      // m_uts_fd = open_ns(uts_path);
    }

    Namespaces::~Namespaces() {
    }

    int Namespaces::open_ns(const fs::path &path) {
      BOOST_LOG_TRIVIAL(debug) << "open_ns: " << path;
      int fd = open(path.string().c_str(), O_RDWR);
      if ( fd < 0 ) // TODO proper exception type
        throw std::runtime_error("Could not open namespace");
      return fd;
    }

    void Namespaces::hostname(const std::string &hn) {
      int err = sethostname(hn.c_str(), hn.size());
      if ( err < 0 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not set hostname to " << hn << ": " << ec;
      }
    }

    void Namespaces::domain_name(const std::string &dn) {
      int err = sethostname(dn.c_str(), dn.size());
      if ( err < 0 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not set domain name to " << dn << ": " << ec;
      }
    }

    void Namespaces::setup_users(uid_t reuid, gid_t regid,
                                 const std::list< UidMapping<uid_t> > &users,
                                 const std::list< UidMapping<gid_t> > &groups) {
      uid_t cur_uid = getuid();
      gid_t cur_gid = getgid();
      if ( cur_uid != 65534 && cur_gid != 65534 )
        BOOST_LOG_TRIVIAL(warning) << "setup_users(): called twice: " << cur_uid << " " << cur_gid;

      std::stringstream uid_map_data, gid_map_data;
      for ( const auto &m: users )
        m.output(uid_map_data);

      for ( const auto &m: groups )
        m.output(gid_map_data);

      std::fstream deny_setgroups("/proc/self/setgroups", std::fstream::out);
      deny_setgroups << "deny";
      deny_setgroups.close();

      // GIDs must be set first, because user enforcement goes into effect when we write uid_map
      std::fstream gid_map("/proc/self/gid_map", std::fstream::out);
      gid_map << gid_map_data.str();
      gid_map.close();

      std::fstream uid_map("/proc/self/uid_map", std::fstream::out);
      uid_map << uid_map_data.str();
      uid_map.close();

      int err = setreuid(reuid, reuid);
      if ( err < 0 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not set UID: " << ec;
      }

      err = setregid(regid, regid);
      if ( err < 0 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not set GID: " << ec;
      }
    }

    void Namespaces::debug_mounts() {
      std::fstream mount_data("/proc/self/mounts", std::fstream::in);
      std::string mount_line;
      BOOST_LOG_TRIVIAL(debug) << "Mounts:";
      while ( std::getline(mount_data, mount_line) ) {
        BOOST_LOG_TRIVIAL(debug) << "  - " << mount_line;
      }
    }

    void Namespaces::debug_routes() {
      std::fstream route_data("/proc/net/route", std::fstream::in);
      std::string route_line;
      BOOST_LOG_TRIVIAL(debug) << "Routes:";
      while ( std::getline(route_data, route_line) ) {
        BOOST_LOG_TRIVIAL(debug) << "  - " << route_line;
      }
    }

    void Namespaces::debug_routes_v6() {
      std::fstream route_data("/proc/net/ipv6_route", std::fstream::in);
      std::string route_line;
      BOOST_LOG_TRIVIAL(debug) << "Routes(IPv6):";
      while ( std::getline(route_data, route_line) ) {
        BOOST_LOG_TRIVIAL(debug) << "  - " << route_line;
      }
    }

    void Namespaces::mount(const fs::path &src, const fs::path &dest,
                           const std::string &type,
                           const MountFlags &options) {

      std::stringstream mount_data;
      std::copy(options.options().cbegin(), options.options().cend(),
                std::ostream_iterator<std::string>(mount_data, ","));
      auto mount_data_str(mount_data.str());
      if ( !options.options().empty() )
        mount_data_str.pop_back(); // Remove trailing comma

      int err = ::mount(src.string().c_str(),
                        dest.string().c_str(),
                        type.c_str(),
                        options.flags(),
                        (void *) mount_data_str.c_str());
      if ( err < 0 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "mount(" << src << ", " << dest << ", " <<
          type << ", " << options.flags() << ", " << mount_data_str << "): failed: " << ec;
      }
    }

    void Namespaces::change_root(const fs::path &new_root) {
      int err = chroot(new_root.string().c_str());
      if ( err < 0 ) {
        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "change_root(" << new_root << "): failed: " << ec;
      }
    }

    NetworkConfigurator Namespaces::network_configuration() const {
      return NetworkConfigurator();
    }

    NetworkDevice Namespaces::loopback_device() const {
      return NetworkDevice("lo");
    }

    // Error category
    class NamespaceCategory : public std::error_category {
    public:
      virtual const char *name() const noexcept {
        return "stork::container::NamespaceCategory";
      };

      virtual std::string message(int value) const override {
        switch ( namespace_errc_t(value) ) {
        case namespace_errc_t::namespace_already_initializing:
          return "Already initializing";
        case namespace_errc_t::namespace_system_error:
          return "System error";
        default:
          return "Unknown error";
        }
      }
    };
    const std::error_category &namespace_error_category() {
      static NamespaceCategory cat;

      return cat;
    }
  }
}
