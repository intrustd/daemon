#ifndef __stork_application_manager_HPP__
#define __stork_application_manager_HPP__

#include <functional>
#include <list>
#include <boost/asio.hpp>

#include "application.hpp"
#include "../backend.hpp"
#include "../queue.hpp"

namespace stork {
  namespace appliance {
    class Appliance;
  }
  namespace application {
    class Manager;

    class RegisteredApplication : public std::enable_shared_from_this<RegisteredApplication> {
    public:
      RegisteredApplication(boost::asio::io_service& svc, Manager &mgr,
                            const ApplicationManifest &mf,
                            std::shared_ptr<backend::IApplication> app);
      ~RegisteredApplication();

      inline const ApplicationManifest &manifest() const { return m_manifest; }

      void update(std::function<void(bool)> callback);

      void schedule_update();
      void schedule_forced_build();

      void async_when_built(std::function<void(boost::system::error_code, boost::filesystem::path&&)> cb);

      //      boost::filesystem::path build();

    private:
      void start_update();

      void do_build();

      boost::asio::io_service &m_io_service;
      Manager &m_manager;

      stork::util::queue m_app_update_strand;

      ApplicationManifest m_manifest;
      std::shared_ptr<backend::IApplication> m_backend_app;

      //      ApplicationVersion m_app_version;

      //      ApplicationMeta m_app_meta;

//       bool m_downloaded;
//
//       int m_download_attempts;
//       boost::gregorian::date m_last_attempted;
//       boost::gregarian::date m_next_attempt;
    };

    class Manager {
    public:
      Manager(boost::asio::io_service &svc, appliance::Appliance &app);
      ~Manager();

      inline appliance::Appliance &appliance() { return m_appliance; }
      inline const appliance::Appliance &appliance() const { return m_appliance; }

      // Transfers ownership as well
      void async_register_application(ApplicationManifest mf,
                                      std::function<void(bool)> callback);
      void async_list_applications(std::function<void(const ApplicationManifest &mf)> on_result,
                                   std::function<void()> on_done);
      void async_get_application(const ApplicationIdentifier &id,
                                 std::function<void(std::shared_ptr<RegisteredApplication>)> cb);

    private:
      void start(); // Read in all application data and schedule updates, etc

      RegisteredApplication *register_application(ApplicationManifest mf, std::shared_ptr<backend::IApplication> app_backend);

      boost::asio::io_service &m_io_service;
      appliance::Appliance &m_appliance;

      boost::asio::io_service::strand m_application_info_strand;
      std::unordered_map<ApplicationIdentifier, std::shared_ptr<RegisteredApplication> > m_applications;
    };
  }
}

#endif
