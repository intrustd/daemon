#ifndef __stork_container_manager_HPP__
#define __stork_container_manager_HPP__

#include <system_error>
#include <boost/asio.hpp>

#include "../backend.hpp"
#include "../queue.hpp"
#include "persona.hpp"
#include "app_instance.hpp"

namespace stork {
  namespace appliance {
    class Appliance;
  }
  namespace container {
    class Manager {
    public:
      Manager(boost::asio::io_service &svc, appliance::Appliance &app);

      enum errc_t {
        container_image_mismatch = 1,
        application_not_found = 2,
        application_would_not_build = 3
      };

      /// Launches the requested container
      ///
      /// This means that a namespace is connected and a root path
      /// constructed (and mounted within the namespace)
      ///
      /// Processes can be launched inside the container
      void async_launch_app_instance(const AppInstanceId &cid,
                                     const boost::filesystem::path &image_path,
                                     std::function<void(std::error_code, std::shared_ptr<AppInstanceMonitor>)> cb);

      void async_launch_persona_container(const backend::PersonaId &pid,
                                          std::function<void(std::error_code, std::shared_ptr<PersonaContainer>)> cb);

      // Builds and launches the container if it is not running
      void async_build_and_launch_app_instance(const AppInstanceId &cid,
                                               std::function<void(std::error_code, std::shared_ptr<AppInstanceMonitor>)> cb);

      inline boost::asio::io_service &service() const { return m_service; }
      inline appliance::Appliance &appliance() const { return m_app; }
      boost::filesystem::path run_directory() const;

      static const std::error_category &error_category();

      bool persona_id_from_ip(const boost::asio::ip::address_v4 &a, backend::PersonaId &id);
      bool app_instance_id_from_ip(const boost::asio::ip::address_v4 &a, AppInstanceId &id);

    private:
      boost::filesystem::path app_instance_work_dir(const AppInstanceId &cid) const;
      boost::filesystem::path app_instance_data_dir(const AppInstanceId &cid) const;

      void notify_app_instance_launches(const AppInstanceId &id,
                                        const boost::asio::ip::address_v4 &a);
      void notify_persona_launches(const backend::PersonaId &id,
                                   const boost::asio::ip::address_v4 &a);

      void init_run_directory();

      boost::asio::io_service &m_service;
      appliance::Appliance    &m_app;

      stork::util::queue m_containers_queue;
      std::unordered_map<AppInstanceId, std::shared_ptr<AppInstance> > m_app_instances;
      std::unordered_map<backend::PersonaId, std::shared_ptr<PersonaContainer> > m_persona_containers;

      boost::shared_mutex m_reverse_ip_mutex;
      std::map<boost::asio::ip::address_v4, AppInstanceId> m_app_instance_ips;
      std::map<boost::asio::ip::address_v4, backend::PersonaId> m_persona_ips;
    };
  }
}

namespace std {
  template<>
  struct is_error_code_enum<stork::container::Manager::errc_t>
    : public std::true_type {};

  inline std::error_code make_error_code(stork::container::Manager::errc_t e) {
    return std::error_code(static_cast<int>(e),
                           stork::container::Manager::error_category());
  }
}

#endif
