#include <boost/random.hpp>
#include <boost/log/utility/manipulators/dump.hpp>
#include <sstream>
#include <set>

#include "app_instance.hpp"
#include "manager.hpp"
#include "runtime.hpp"
#include "../appliance.hpp"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace stork {
  namespace container {
    // AppInstanceInitializer

    class AppInstanceInitializer : public NamespacesInitializer {
    public:
      AppInstanceInitializer(AppInstance &c)
        : m_app_instance(c) {
      }

    protected:
      virtual void setup(Namespaces &ns, int comm) {
        const fs::path &image_path(m_app_instance.image_path());

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

        ns.mount(m_app_instance.manager().appliance().app_instance_init_path(),
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
          exit(1);
        }

        // set host name
        ns.hostname(m_app_instance.app_instance_id().app_id().app_id());
        ns.domain_name(m_app_instance.app_instance_id().app_id().domain());

        auto &bridger(m_app_instance.manager().appliance().bridge_controller());
        std::error_code net_ec = bridger.set_up_networking();
        if ( net_ec ) {
          BOOST_LOG_TRIVIAL(error) << "Could not set up networking: " << net_ec;
        }

        int netns_fd = open("/proc/self/ns/net", 0);
        if ( netns_fd < 0 ) {
          auto ec(errno);
          BOOST_LOG_TRIVIAL(error) << "Could not open network namespace: " << ec;
          exit(1);
        }
        BridgeController::ArpEntry arp;
        bridger.create_veth_to_ns(netns_fd, ns.bridge_port(), ns.ip(), "eth0", arp);
        close(netns_fd);

        bridger.send_arp_entry_over_socket(comm, arp);

        // Exec stork-init

        BOOST_LOG_TRIVIAL(debug) << "Running stork-init...";

        err = dup2(comm, 3);
        if ( err == -1 ) {
          BOOST_LOG_TRIVIAL(error) << "Could not duplicate comm as 3";
        }

        close(comm);

        execl("/stork/stork-init", "stork-init",
              m_app_instance.app_instance_id().persona_id().id().c_str(),
              m_app_instance.app_instance_id().app_id().app_id().c_str(),
              m_app_instance.app_instance_id().app_id().domain().c_str(),
              NULL);

        auto ec(errno);
        BOOST_LOG_TRIVIAL(error) << "Could not execute stork-init: " << ec;
        exit(1);
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

      AppInstance &m_app_instance;
    };

    // AppInstance

    AppInstance::AppInstance(container::Manager &manager, const AppInstanceId &id,
                         const fs::path &image_path,
                         const fs::path &work_path,
                         const fs::path &local_data_path)
      : m_manager(manager), m_app_instance_id(id),
        m_setup_complete(false), m_setup_started(false),
        m_setup_queue(manager.service()),
        m_image_path(image_path), m_work_path(work_path), m_local_data_path(local_data_path) {

    }

    void AppInstance::async_setup(std::function<void(std::error_code)> cb) {
      if ( m_setup_started.exchange(true) ) {
        m_setup_queue.dispatch([this, cb{std::move(cb)}] (util::queue::reason r) {
            if ( r.normal() ) {
              cb(std::error_code());
              m_setup_queue.async_restart();
            } else {
              cb(std::make_error_code(container_setup_cancelled));
              m_setup_queue.async_restart();
            }
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
                auto initializer(std::make_shared<AppInstanceInitializer>(*this));
                auto &bridger(manager().appliance().bridge_controller());
                initializer->async_setup_namespaces
                  (bridger,
                   [this, &bridger, cb{std::move(cb)}, initializer]
                   (std::error_code ec, pid_t child_proc, int management_end) {
                    if ( ec ) {
                      BOOST_LOG_TRIVIAL(error) << "Could not set container: " << ec;
                    } else {
                      BOOST_LOG_TRIVIAL(debug) << "Set up container and received management socket: " << management_end;

                      BridgeController::ArpEntry arp(bridger.add_arp_from_socket(management_end));
                      m_ip_address = boost::asio::ip::address_v4(arp.first);

                      // Start wait on container
                      // TODO make this atomic
                      m_monitor = std::make_shared<AppInstanceMonitor>(*this, child_proc, management_end);
                      m_setup_complete.store(true);
                      m_monitor->async_start();

                      cb(ec);
                      m_setup_queue.async_restart();
                    }
                  });
              }
            } else {
              cb(std::make_error_code(container_setup_cancelled));
              m_setup_queue.async_restart();
            }
          });
      }
    }

    void AppInstance::async_after_launch(std::function<void(std::error_code, std::shared_ptr<AppInstanceMonitor>)> cb) {
      if ( m_setup_started.load() ) {
        m_setup_queue.post([this, cb{std::move(cb)}] (util::queue::reason r) {
            if ( r.normal() ) {
              if ( m_setup_complete.load() ) {
                cb(std::error_code(), m_monitor);
                m_setup_queue.async_restart();
              } else {
                cb(std::make_error_code(container_not_launching), std::shared_ptr<AppInstanceMonitor>());
                m_setup_queue.async_restart();
              }
            } else {
              cb(std::make_error_code(container_setup_cancelled), std::shared_ptr<AppInstanceMonitor>());
              m_setup_queue.async_restart();
            }
          });
      } else {
        cb(std::make_error_code(container_not_launching), std::shared_ptr<AppInstanceMonitor>());
        m_setup_queue.async_restart();
      }
    }

    // AppInstanceMonitor
    AppInstanceMonitor::AppInstanceMonitor(AppInstance &c, pid_t init_pid, int comm_fd)
      : m_owner(c), m_init_process(init_pid),
        m_comm(c.manager().service(), boost::asio::local::datagram_protocol(), comm_fd),
        m_tun_fd(-1) {
    }

    AppInstanceMonitor::~AppInstanceMonitor() {
      if ( m_init_process.running() )
        BOOST_LOG_TRIVIAL(warning) << "AppInstanceMonitor exiting while process is still running";

      if ( m_tun_fd > 0 ) close(m_tun_fd);

      // TODO notify container that the monitor has failed
    }

    void AppInstanceMonitor::async_start() {
      m_comm.async_wait(boost::asio::local::datagram_protocol::socket::wait_read,
                        boost::bind(&AppInstanceMonitor::recv_comm_handshake, shared_from_this(), boost::placeholders::_1));
    }

    void AppInstanceMonitor::recv_comm_handshake(boost::system::error_code ec) {
      if ( ec ) {
        BOOST_LOG_TRIVIAL(error) << "AppInstance monitor error: " << ec;
        // TODO signal container something happened
      } else {
        auto comm_fd(m_comm.native_handle());
        uint8_t sts;

        int err = recv(comm_fd, &sts, sizeof(sts), 0);
        if ( err < 0 ) {
          auto errno_(errno);
          BOOST_LOG_TRIVIAL(error) << "recv_comm_handshake(): failed: " << errno_;
        }
      }
    }

    class ContainerErrorCategory : public std::error_category {
    public:
      virtual const char *name() const noexcept {
        return "stork::container::ContainerErrorCategory";
      }

      virtual std::string message(int value) const override {
        switch ( AppInstance::errc_t(value) ) {
        case AppInstance::container_setup_cancelled:
          return "Container setup cancelled";
        case AppInstance::container_not_launching:
          return "Container not launching";
        default:
          return "Unknown error";
        }
      }
    };

    const std::error_category &AppInstance::error_category() {
      static ContainerErrorCategory ec;
      return ec;
    }
  }
}

namespace std {
  std::size_t hash<stork::container::AppInstanceId>::operator() (const stork::container::AppInstanceId &id) const {
    return hash<stork::backend::PersonaId>()(id.persona_id()) ^ hash<stork::application::ApplicationIdentifier>()(id.app_id());
  }
}
