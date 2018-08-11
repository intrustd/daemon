#include <boost/random.hpp>
#include <boost/log/utility/manipulators/dump.hpp>
#include <sstream>
#include <set>

#include "container.hpp"
#include "manager.hpp"
#include "runtime.hpp"
#include "../appliance.hpp"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace stork {
  namespace container {
    // ContainerInitializer

    class ContainerInitializer : public NamespacesInitializer {
    public:
      ContainerInitializer(Container &c)
        : m_container(c) {
      }

    protected:
      static boost::asio::ip::address_v6 random_ip6_addr() {
        boost::asio::ip::address_v6::bytes_type raw_addr;

        static boost::random::mt19937 rng;
        static boost::random::uniform_int_distribution<std::uint8_t> gen;
        static bool seeded = false;

        if ( !seeded ) {
          // TODO thread safety;
          rng.seed(std::time(0));
          seeded = true;
        }

        std::generate(raw_addr.begin() + 1, raw_addr.end(), boost::bind(gen, rng));

        raw_addr[0] = 0xFE;

        raw_addr[1] &= 0xC0;
        raw_addr[1] |= 0x80;

        return boost::asio::ip::address_v6(raw_addr);
      }

      virtual void setup(Namespaces &ns, int comm) {
        const fs::path &image_path(m_container.image_path());

        std::list< UidMapping<uid_t> > users{
          UidMapping<uid_t>(0, ns.init_data().root_uid, 1)
        };
        std::list< UidMapping<gid_t> > groups{
          UidMapping<gid_t>(0, ns.init_data().root_gid, 1)
        };

        ns.setup_users(0, 0, users, groups);

        ns.mount("/nix", image_path / "nix", "bind",
                 MountFlags().bind().rec().ro());
        ns.mount("proc", image_path / "proc", "proc", MountFlags());
        ns.mount("tmpfs", image_path / "dev", "tmpfs",
                 MountFlags().nosuid()
                   .strictatime().option("mode", "755")
                   .option("size", "65536k"));

        fs::create_directories(image_path / "dev" / "net");
        std::fstream tun_f((image_path / "dev" / "net" / "tun").string(), std::fstream::out);
        tun_f << " ";
        tun_f.close();
        ns.mount("/dev/net/tun", image_path / "dev" / "net" / "tun", "bind",
                 MountFlags().bind());

        fs::create_directories(image_path / "dev" / "pts");
        fs::create_directories(image_path / "dev" / "shm");
        fs::create_directories(image_path / "dev" / "mqueue");

        ns.mount("devpts", image_path / "dev" / "pts", "devpts",
                 MountFlags()
                   .nosuid().noexec().option("newinstance")
                   .option("ptmxmode", "0666").option("mode", "0620")
                   .option("gid", "0")); // TODO figure out group id
        ns.mount("shm", image_path / "dev" / "shm", "tmpfs",
                 MountFlags()
                   .nosuid().noexec().nodev()
                   .option("mode", "1777").option("size", "65536k"));
        ns.mount("mqueue", image_path / "dev"/ "mqueue", "mqueue",
                 MountFlags().nosuid().noexec().nodev());
        ns.mount("sysfs", image_path / "sys", "sysfs",
                 MountFlags().nosuid().noexec().nodev().ro());

        fs::create_directories(image_path / "sys" / "fs" / "cgroup");
        ns.mount("cgroup", image_path / "sys" / "fs" / "cgroup", "cgroup",
                 MountFlags().nosuid().noexec().nodev().relatime().ro().option("all"));

        ns.mount("tmpfs", image_path / "stork", "tmpfs",
                 MountFlags().nodev().option("size", "65536k").option("mode", "777"));
        std::fstream stork_init_mount((image_path / "stork" / "stork-init").string(), std::fstream::out);
        stork_init_mount.close();

        ns.mount(m_container.manager().appliance().stork_init_path(),
                 image_path / "stork" / "stork-init", "bind",
                 MountFlags().bind());

        // TODO mount data partition
        // ns.mount(m_container.local_data_path(), image_path / "stork" / "data", "bind",
        //          MountFlags().bind())

        ns.change_root(image_path);
        int err = chdir("/");
        if ( err < 0 ) {
          auto ec(errno);
          BOOST_LOG_TRIVIAL(error) << "Could not change root to /: " << ec;
        }

        // set host name
        ns.hostname(m_container.container_id().app_id().app_id());
        ns.domain_name(m_container.container_id().app_id().domain());

        // Create network device
        TunDevice tun;
        auto net_conf(ns.network_configuration());
        if ( !tun.is_valid() ) {
          BOOST_LOG_TRIVIAL(error) << "Could not create tun device. Canceling container start";
          return;
        } else {
          BOOST_LOG_TRIVIAL(debug) << "Created tun device " << tun.device_name();

          auto tun_addr(random_ip6_addr());
          BOOST_LOG_TRIVIAL(debug) << "Assigning tun device address: " << tun_addr;

          net_conf(tun).add_address(tun_addr, 10)
            .bring_up();

          // Route all IPv4 and IPv6 traffic through this device
        }

        // Bring up loopback device
        net_conf(ns.loopback_device()).bring_up();

        // TODO for some reason this makes things work???
        system("/bin/ip -f inet6 route");

        BOOST_LOG_TRIVIAL(debug) << "Closing all file descriptors";
        auto open_fds(collect_open_fds());
        open_fds.erase(1);
        open_fds.erase(2);
        open_fds.erase(tun.tun_fd());
        open_fds.erase(comm);

        std::for_each(open_fds.begin(), open_fds.end(), close);

        // Exec stork-init

        if ( tun.is_valid() ) {
          std::stringstream tun_string, comm_string;
          tun_string << tun.steal();
          comm_string << comm;

          BOOST_LOG_TRIVIAL(debug) << "Running stork-init...";

          execl("/stork/stork-init", "stork-init", "--comm", comm_string.str().c_str(), "--tun", tun_string.str().c_str(), NULL);

          auto ec(errno);
          BOOST_LOG_TRIVIAL(error) << "Could not execute stork-init: " << ec;
        } else
          BOOST_LOG_TRIVIAL(error) << "The tunnel device is invalid. Cannot configure any more. Container exiting";

        // TODO close all file descriptors, including stdin, stdout
        // and stderr, move to using an output file for each, and then
        // run the stork init program
      }

    private:
      std::set<int> collect_open_fds() {
        std::set<int> r;
        for ( const auto &fd: fs::directory_iterator("/proc/self/fd") ) {
          // We must do this lazily, or we risk closing the directory iterator
          int fd_raw;
          std::stringstream ss(fd.path().filename().string());
          ss >> fd_raw;
          r.insert(fd_raw);
        }
        return r;
      }

      Container &m_container;
    };

    // Container

    Container::Container(container::Manager &manager, const ContainerId &id,
                         const fs::path &image_path,
                         const fs::path &work_path,
                         const fs::path &local_data_path)
      : m_manager(manager), m_container_id(id),
        m_setup_complete(false), m_setup_started(false),
        m_setup_queue(manager.service()),
        m_image_path(image_path), m_work_path(work_path), m_local_data_path(local_data_path) {

      m_mounts.push_back(Mount("/nix", "/nix").add_option("bind"));
      m_mounts.push_back(Mount("proc", "/proc", "proc"));
      m_mounts.push_back(Mount("tmpfs", "/dev", "tmpfs").
                         add_option("nosuid").add_option("strictatime").
                         add_option("mode", "755").
                         add_option("size", "65536k"));
      m_mounts.push_back(Mount("devpts", "/dev/pts", "devpts").
                         add_option("nosuid").add_option("noexec").
                         add_option("newinstance").add_option("ptmxmode", "0666").
                         add_option("mode", "0620").add_option("gid", "5"));
      m_mounts.push_back(Mount("shm", "/dev/shm", "tmpfs").
                         add_option("nosuid").add_option("noexec").
                         add_option("nodev").add_option("mode", "1777").
                         add_option("size", "65536k"));
      m_mounts.push_back(Mount("mqueue", "/dev/mqueue", "mqueue").
                         add_option("nosuid").add_option("noexec").
                         add_option("nodev"));
      m_mounts.push_back(Mount("sysfs", "/sys", "sysfs").
                         add_option("nosuid").add_option("noexec").
                         add_option("nodev").add_option("ro"));
      m_mounts.push_back(Mount("cgroup", "/sys/fs/cgroup", "cgroup").
                         add_option("nosuid").add_option("noexec").
                         add_option("nodev").add_option("relatime").
                         add_option("ro"));
    }

    void Container::write_oci_spec(pt::ptree &pt) {

      pt.put("ociVersion", "1.0.0");
      pt::ptree process;
      process.put("terminal", true);

      pt::ptree process_user;
      process_user.put("uid", 0);
      process_user.put("gid", 0);
      process.put_child("user", std::move(process_user));

      pt::ptree process_args, process_arg;
      process_arg.put_value("bash"); // TODO custom command
      process_args.push_back(std::make_pair("", process_arg));
      process.put_child("args", std::move(process_args));

      // TODO environment variables
      pt::ptree process_env;
      write_process_env(process_env);
      process.put_child("env", std::move(process_env));

      process.put("cwd", "/"); // TODO CWD

      pt::ptree process_capabilities;
      write_process_capabilities(process_capabilities);
      process.put_child("capabilities", std::move(process_capabilities));

      pt::ptree process_rlimits;
      write_process_rlimits(process_rlimits);
      process.put_child("rlimits", std::move(process_rlimits));

      process.put("noNewPrivileges", true); // TODO Figure out what this does
      pt.put_child("process", std::move(process));

      pt::ptree root;
      root.put("path", "/home/tathougies/root_path"); // TODO root path
      root.put("readonly", true); // TODO should this be false?
      pt.put_child("root", std::move(root));

      pt.put("hostname", m_hostname);

      pt::ptree mounts;
      write_mounts(mounts);
      pt.put_child("mounts", std::move(mounts));

      pt::ptree linux, linux_uid_mappings, linux_gid_mappings;
      write_mappings(m_uid_map, linux_uid_mappings);
      write_mappings(m_gid_map, linux_gid_mappings);
      linux.put_child("uidMappings", std::move(linux_uid_mappings));
      linux.put_child("gidMappings", std::move(linux_gid_mappings));

      linux.put("namespaces..type", "pid");
      linux.put("namespaces..type", "ipc");
      linux.put("namespaces..type", "uts");
      linux.put("namespaces..type", "mount");
      linux.put("namespaces..type", "user");

      linux.put("maskedPaths", "/proc/kcore");
      linux.put("maskedPaths", "/proc/latency_stats");
      linux.put("maskedPaths", "/proc/timer_list");
      linux.put("maskedPaths", "/proc/timer_stats");
      linux.put("maskedPaths", "/proc/sched_debug");
      linux.put("maskedPaths", "/sys/firmware");

      linux.put("readonlyPaths", "/proc/asound");
      linux.put("readonlyPaths", "/proc/bus");
      linux.put("readonlyPaths", "/proc/fs");
      linux.put("readonlyPaths", "/proc/irq");
      linux.put("readonlyPaths", "/proc/sys");
      linux.put("readonlyPaths", "/proc/sysrq-trigger");

      pt.put_child("linux", std::move(linux));
    }

    void Container::write_process_env(pt::ptree &pt) {
      pt::ptree path;
      path.put_value("PATH=/sw/bin");
      pt.push_back(std::make_pair("", std::move(path)));
    }

    void Container::write_process_rlimits(pt::ptree &pt) {
      pt::ptree nofiles;
      nofiles.put("type", "RLIMIT_NOFILE");
      nofiles.put("hard", 1024);
      nofiles.put("soft", 1024);

      pt.push_back(std::make_pair("", std::move(nofiles)));
    }

    void Container::write_process_capabilities(pt::ptree &pt) {
      pt.put("bounding.", "CAP_AUDIT_WRITE");
      pt.put("bounding.", "CAP_KILL");
      pt.put("bounding.", "CAP_NET_BIND_SERVICE");
      pt.put("effective.", "CAP_AUDIT_WRITE");
      pt.put("effective.", "CAP_KILL");
      pt.put("effective.", "CAP_NET_BIND_SERVICE");
      pt.put("inheritable.", "CAP_AUDIT_WRITE");
      pt.put("inheritable.", "CAP_KILL");
      pt.put("inheritable.", "CAP_NET_BIND_SERVICE");
      pt.put("permitted.", "CAP_AUDIT_WRITE");
      pt.put("permitted.", "CAP_KILL");
      pt.put("permitted.", "CAP_NET_BIND_SERVICE");
      pt.put("ambient.", "CAP_AUDIT_WRITE");
      pt.put("ambient.", "CAP_KILL");
      pt.put("ambient.", "CAP_NET_BIND_SERVICE");
    }

    void Container::write_mounts(pt::ptree &pt) {
      for ( const auto &mount: m_mounts ) {
        pt::ptree mount_pt;
        mount.write_oci_mount_spec(mount_pt);
        pt.push_back(std::make_pair("", std::move(mount_pt)));
      }
    }

    void Container::write_mappings(std::list< UidGidMapping > &id_map, pt::ptree &pt) {
      for ( const auto &mapping: id_map ) {
        pt::ptree mapping_pt;
        mapping.write_oci_mapping_spec(mapping_pt);
        pt.push_back(std::make_pair("", std::move(mapping_pt)));
      }
    }

    void Container::async_setup(std::function<void(std::error_code)> cb) {
      if ( m_setup_started.exchange(true) ) {
        m_setup_queue.dispatch([cb{std::move(cb)}] (util::queue::reason r) {
            if ( r.normal() ) cb(std::error_code());
            else cb(std::make_error_code(container_setup_cancelled));
          });
      } else {
        // Use NamespacesInitializer
        m_setup_queue.dispatch([this, cb{std::move(cb)}] (util::queue::reason r) {
            if ( r.normal() ) {
              if ( m_setup_complete ) {
                cb(std::error_code());
                m_setup_queue.async_restart();
              } else {
                // Run set up
                auto initializer(std::make_shared<ContainerInitializer>(*this));
                initializer->async_setup_namespaces
                  ([this, cb{std::move(cb)}, initializer] (std::error_code ec, pid_t child_proc, int management_end) {
                    if ( ec ) {
                      BOOST_LOG_TRIVIAL(error) << "Could not set container: " << ec;
                    } else {
                      BOOST_LOG_TRIVIAL(debug) << "Set up container and received management socket: " << management_end;

                      // Start wait on container
                      // TODO make this atomic
                      m_monitor = std::make_shared<ContainerMonitor>(*this, child_proc, management_end);
                      m_setup_complete.store(true);
                      m_monitor->async_start();

                      cb(ec);
                    }
                  });
              }
            } else
              cb(std::make_error_code(container_setup_cancelled));
          });
      }
    }

    void Container::async_after_launch(std::function<void(std::error_code, std::shared_ptr<ContainerMonitor>)> cb) {
      if ( m_setup_started.load() ) {
        m_setup_queue.post([this, cb{std::move(cb)}] (util::queue::reason r) {
            if ( r.normal() ) {
              if ( m_setup_complete.load() ) {
                cb(std::error_code(), m_monitor);
              } else {
                cb(std::make_error_code(container_not_launching), std::shared_ptr<ContainerMonitor>());
                m_setup_queue.async_restart();
              }
            } else
              cb(std::make_error_code(container_setup_cancelled), std::shared_ptr<ContainerMonitor>());
          });
      } else {
        cb(std::make_error_code(container_not_launching), std::shared_ptr<ContainerMonitor>());
      }
    }

    // ContainerMonitor
    ContainerMonitor::ContainerMonitor(Container &c, pid_t init_pid, int comm_fd)
      : m_owner(c), m_init_process(init_pid),
        m_comm(c.manager().service(), boost::asio::local::datagram_protocol(), comm_fd),
        m_tun_fd(-1) {
    }

    ContainerMonitor::~ContainerMonitor() {
      if ( m_init_process.running() )
        BOOST_LOG_TRIVIAL(warning) << "ContainerMonitor exiting while process is still running";

      if ( m_tun_fd > 0 ) close(m_tun_fd);

      // TODO notify container that the monitor has failed
    }

    void ContainerMonitor::async_start() {
      // First, do the handshake with stork-init to retrieve the TUN device.
      // Then start the service
      m_comm.async_wait(boost::asio::local::datagram_protocol::socket::wait_read,
                        boost::bind(&ContainerMonitor::recv_comm_handshake, shared_from_this(), boost::placeholders::_1));
    }

    void ContainerMonitor::recv_comm_handshake(boost::system::error_code ec) {
      if ( ec ) {
        BOOST_LOG_TRIVIAL(error) << "Container monitor error: " << ec;
        // TODO signal container something happened
      } else {
        auto comm_fd(m_comm.native_handle());

        std::uint32_t cookie(0);

        std::uint8_t cbuf[CMSG_LEN(sizeof(int))];
        struct msghdr msg = { 0 };
        struct iovec io[] = { { .iov_base = &cookie, .iov_len = sizeof(cookie) } };
        msg.msg_iov = io;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf;
        msg.msg_controllen = sizeof(cbuf);

        int err = recvmsg(comm_fd, &msg, 0);
        if ( err < 0 ) {
          auto errno_(errno);
          BOOST_LOG_TRIVIAL(error) << "recv_comm_handshake(): failed: " << errno_;
          // TODO signal container error
        } else {
          struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
          if ( !cmsg || cmsg->cmsg_level != SOL_SOCKET ||
               cmsg->cmsg_type != SCM_RIGHTS || cookie != 0xDEADBEEF ) {
            BOOST_LOG_TRIVIAL(error) << "recv_comm_handshake(): failed: No control message";
            /// TODO signal container error
          } else {
            int *tun_fd_ptr = (int *) CMSG_DATA(cmsg);
            m_tun_fd = *tun_fd_ptr;

            BOOST_LOG_TRIVIAL(info) << "Got tun fd: " << m_tun_fd;

            msg.msg_control = NULL;
            msg.msg_controllen = 0;

            err = sendmsg(comm_fd, &msg, 0);
            if ( err < 0 ) {
              auto errno_(errno);
              BOOST_LOG_TRIVIAL(error) << "recv_comm_handshake(): failed: Could not send ack: " << errno_;
              // TODO signal container error
            }

            BOOST_LOG_TRIVIAL(debug) << "Sent ack";
            // Now start all services
          }
        }
      }
    }

    class ContainerErrorCategory : public std::error_category {
    public:
      virtual const char *name() const noexcept {
        return "stork::container::ContainerErrorCategory";
      }

      virtual std::string message(int value) const override {
        switch ( Container::errc_t(value) ) {
        case Container::container_setup_cancelled:
          return "Container setup cancelled";
        case Container::container_not_launching:
          return "Container not launching";
        default:
          return "Unknown error";
        }
      }
    };

    const std::error_category &Container::error_category() {
      static ContainerErrorCategory ec;
      return ec;
    }

    // Mount

    Container::Mount::Mount(const fs::path &host_path,
                            const fs::path &container_path)
      : m_source_path(host_path), m_destination_path(container_path),
        m_mount_type("bind"), m_mount_options{"bind"} {
    }

    Container::Mount::Mount(const fs::path &source_path, const fs::path &dest_path,
                            const std::string &type)
      : m_source_path(source_path), m_destination_path(dest_path),
        m_mount_type(type) {
    }

    Container::Mount &Container::Mount::add_option(const std::string &option) {
      m_mount_options.push_back(option);
      return *this;
    }

    Container::Mount &Container::Mount::add_option(const std::string &option, const std::string &value) {
      std::stringstream option_name;
      option_name << option << "=" << value;
      return add_option(option_name.str());
    }

    void Container::Mount::write_oci_mount_spec(pt::ptree &pt) const {
      pt.put("source", m_source_path.string());
      pt.put("destination", m_destination_path.string());
      pt.put("type", m_mount_type);

      pt::ptree opts_pt;
      for ( const auto &option: m_mount_options ) {
        pt::ptree opt_pt;
        opt_pt.put_value(option);
        opts_pt.push_back(std::make_pair("", std::move(opt_pt)));
      }
      pt.put_child("options", std::move(opts_pt));
    }

    // UidGidMapping

    Container::UidGidMapping::UidGidMapping(uid_t host, uid_t container, uid_t sz)
      : m_host_id(host), m_container_id(container), m_sz(sz) {
    }

    void Container::UidGidMapping::write_oci_mapping_spec(pt::ptree &pt) const {
      pt.put("hostID", m_host_id);
      pt.put("containerID", m_container_id);
      pt.put("size", m_sz);
    }
  }
}

namespace std {
  std::size_t hash<stork::container::ContainerId>::operator() (const stork::container::ContainerId &id) const {
    return hash<string>()(id.persona_id().id()) ^ hash<stork::application::ApplicationIdentifier>()(id.app_id());
  }
}
