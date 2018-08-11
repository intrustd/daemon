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

    class ContainerId {
    public:
      inline ContainerId(const backend::PersonaId &persona_id,
                         const application::ApplicationIdentifier &app_id)
        : m_persona_id(persona_id),
          m_app_id(app_id) {
      }

      inline const backend::PersonaId &persona_id() const { return m_persona_id; }
      inline const application::ApplicationIdentifier &app_id() const { return m_app_id; }

      inline bool operator ==(const ContainerId &b) const {
        return m_persona_id == b.m_persona_id &&
          m_app_id == b.m_app_id;
      }

    private:
      backend::PersonaId m_persona_id;
      application::ApplicationIdentifier m_app_id;
    };

    class Container;

    /**
     * Monitor for a running container
     */
    class ContainerMonitor : public std::enable_shared_from_this<ContainerMonitor> {
    public:
      ContainerMonitor(Container &c, pid_t init_pid, int comm_fd);
      ~ContainerMonitor();

      inline Container &owner() const { return m_owner; }
      inline const boost::process::child &init_process() const { return m_init_process; }

      void async_start();

    private:
      void recv_comm_handshake(boost::system::error_code ec);

      Container &m_owner;

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
    class Container {
    public:
      enum errc_t {
        container_setup_cancelled = 1,
        container_not_launching = 2
      };

      Container(container::Manager &manager, const ContainerId &id,
                const boost::filesystem::path &image_path,
                const boost::filesystem::path &work_path,
                const boost::filesystem::path &local_data_path);

      void write_oci_spec(boost::property_tree::ptree &pt);

      static const std::error_category &error_category();

      class Mount {
      public:
        Mount(const boost::filesystem::path &host_path,
              const boost::filesystem::path &container_path);
        Mount(const boost::filesystem::path &source_path,
              const boost::filesystem::path &destination_path,
              const std::string &type);

        inline const boost::filesystem::path &source_path() const { return m_source_path; }
        inline const boost::filesystem::path &destination_path() const { return m_destination_path; }
        inline const std::string &mount_type() const { return m_mount_type; }
        inline const std::list<std::string> &options() const { return m_mount_options; }

        Mount &add_option(const std::string &option);
        Mount &add_option(const std::string &option_name, const std::string &option_value);

        void write_oci_mount_spec(boost::property_tree::ptree &pt) const;

      private:
        boost::filesystem::path m_source_path, m_destination_path;
        std::string m_mount_type;
        std::list<std::string> m_mount_options;
      };

      class UidGidMapping {
      public:
        UidGidMapping(uid_t host, uid_t container, uid_t sz);

        inline uid_t host_id() const { return m_host_id; }
        inline uid_t container_id() const { return m_container_id; }
        inline uid_t size() const { return m_sz; }

        void write_oci_mapping_spec(boost::property_tree::ptree &pt) const;

      private:
        uid_t m_host_id, m_container_id, m_sz;
      };

      inline const ContainerId &container_id() const { return m_container_id; }
      inline container::Manager &manager() const { return m_manager; }
      inline const boost::filesystem::path &image_path() const { return m_image_path; }
      inline const boost::filesystem::path &work_path() const { return m_work_path; }
      inline const boost::filesystem::path &local_data_path() const { return m_local_data_path; }

    private:

      void async_setup(std::function<void(std::error_code)> cb);
      void async_after_launch(std::function<void(std::error_code, std::shared_ptr<ContainerMonitor>)> cb);

      void write_process_env(boost::property_tree::ptree &pt);
      void write_process_capabilities(boost::property_tree::ptree &pt);
      void write_process_rlimits(boost::property_tree::ptree &pt);
      void write_mounts(boost::property_tree::ptree &pt);
      void write_mappings(std::list< UidGidMapping > &id_map, boost::property_tree::ptree &pt);

      container::Manager &m_manager;
      ContainerId m_container_id;

      std::atomic_bool m_setup_complete, m_setup_started;
      std::shared_ptr<ContainerMonitor> m_monitor;
      // TODO m_monitor and m_setup_complete/started need to be changed atomically. A lock is required

      stork::util::queue m_setup_queue;

      boost::filesystem::path m_image_path, m_work_path;
      boost::filesystem::path m_local_data_path;

      std::string m_hostname;

      std::list< Mount > m_mounts;
      std::list< UidGidMapping > m_uid_map, m_gid_map;

      friend class Manager;
    };
  }
}

namespace std {
  template<>
  struct is_error_code_enum<stork::container::Container::errc_t>
    : public std::true_type {};

  inline std::error_code make_error_code(stork::container::Container::errc_t e) {
    return std::error_code(static_cast<int>(e),
                           stork::container::Container::error_category());
  }

  template <>
  struct hash<stork::container::ContainerId> {
    std::size_t operator() (const stork::container::ContainerId &) const;
  };
}

#endif
