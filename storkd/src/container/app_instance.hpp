#ifndef __stork_container_container_HPP__
#define __stork_container_container_HPP__

#include <list>
#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/process.hpp>

#include "../backend.hpp"
#include "../queue.hpp"
#include "../application/application.hpp"

namespace stork {
  namespace container {
    class Manager;

    class AppInstanceId {
    public:
      inline AppInstanceId(const backend::PersonaId &persona_id,
                           const application::ApplicationIdentifier &app_id)
        : m_persona_id(persona_id),
          m_app_id(app_id) {
      }
      inline AppInstanceId() { }

      inline const backend::PersonaId &persona_id() const { return m_persona_id; }
      inline const application::ApplicationIdentifier &app_id() const { return m_app_id; }

      inline bool is_valid() const { return m_persona_id.is_valid(); }

      inline bool operator ==(const AppInstanceId &b) const {
        return m_persona_id == b.m_persona_id &&
          m_app_id == b.m_app_id;
      }

    private:
      backend::PersonaId m_persona_id;
      application::ApplicationIdentifier m_app_id;
    };

    class AppInstance;

    /**
     * Monitor for a running container
     */
    class AppInstanceMonitor : public std::enable_shared_from_this<AppInstanceMonitor> {
    public:
      AppInstanceMonitor(AppInstance &c, pid_t init_pid, int comm_fd);
      ~AppInstanceMonitor();

      inline AppInstance &owner() const { return m_owner; }
      inline const boost::process::child &init_process() const { return m_init_process; }

      void async_start();

    private:
      void recv_comm_handshake(boost::system::error_code ec);

      AppInstance &m_owner;

      // TODO figure out how to wait on this (may need to use sigchld_service)
      boost::process::child m_init_process;
      boost::asio::local::datagram_protocol::socket m_comm;
      int m_tun_fd;
    };

    /**
     * A container consists of an immutable root_path within the nix store and a command to run
     *
     * A container also needs a directory where it can create a new
     * (temporary) directory for the running container
     *
     * Upon starting, a container receives an ID
     */
    class AppInstance {
    public:
      enum errc_t {
        container_setup_cancelled = 1,
        container_not_launching = 2
      };

      AppInstance(container::Manager &manager, const AppInstanceId &id,
                  const boost::filesystem::path &image_path,
                  const boost::filesystem::path &work_path,
                  const boost::filesystem::path &local_data_path);

      static const std::error_category &error_category();

      inline const AppInstanceId &app_instance_id() const { return m_app_instance_id; }
      inline container::Manager &manager() const { return m_manager; }
      inline const boost::filesystem::path &image_path() const { return m_image_path; }
      inline const boost::filesystem::path &work_path() const { return m_work_path; }
      inline const boost::filesystem::path &local_data_path() const { return m_local_data_path; }
      inline const boost::asio::ip::address_v4 &ip_address() const { return m_ip_address; }

    private:

      void async_setup(std::function<void(std::error_code)> cb);
      void async_after_launch(std::function<void(std::error_code, std::shared_ptr<AppInstanceMonitor>)> cb);

      container::Manager &m_manager;
      AppInstanceId m_app_instance_id;

      std::atomic_bool m_setup_complete, m_setup_started;
      std::shared_ptr<AppInstanceMonitor> m_monitor;
      // TODO m_monitor and m_setup_complete/started need to be changed atomically. A lock is required

      stork::util::queue m_setup_queue;

      boost::filesystem::path m_image_path, m_work_path;
      boost::filesystem::path m_local_data_path;

      boost::asio::ip::address_v4 m_ip_address;

      friend class Manager;
    };
  }
}

namespace std {
  template<>
  struct is_error_code_enum<stork::container::AppInstance::errc_t>
    : public std::true_type {};

  inline std::error_code make_error_code(stork::container::AppInstance::errc_t e) {
    return std::error_code(static_cast<int>(e),
                           stork::container::AppInstance::error_category());
  }

  template <>
  struct hash<stork::container::AppInstanceId> {
    std::size_t operator() (const stork::container::AppInstanceId &) const;
  };
}

#endif
