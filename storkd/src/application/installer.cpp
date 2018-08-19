#include <boost/bind.hpp>
#include "installer.hpp"

namespace stork {
  namespace application {
    ApplicationInstaller::ApplicationInstaller(appliance::Appliance &app, const backend::PersonaId &persona,
                                               const ApplicationIdentifier &app_id,
                                               std::function<void(std::error_code)> &&cb)
      : m_appliance(app), m_persona_id(persona),
        m_app_id(app_id), m_callback(std::move(cb)) {
    }

    ApplicationInstaller::~ApplicationInstaller() {
    }

    void ApplicationInstaller::async_install() {
      auto shared(shared_from_this());
      m_appliance.backend().async_get_persona
        (m_persona_id, boost::bind(&ApplicationInstaller::got_persona, shared_from_this(),
                                   boost::placeholders::_1));
    }

    void ApplicationInstaller::got_persona(std::shared_ptr<backend::IPersona> p) {
      if ( p ) {
        m_persona = p;

        m_appliance.container_mgr().async_build_and_launch_app_instance
          (app_instance_id(),
           boost::bind(&ApplicationInstaller::application_container_launched, shared_from_this(),
                       boost::placeholders::_1, boost::placeholders::_2));
      } else {
        // TODO better errors
        m_callback(std::make_error_code(std::errc::identifier_removed));
      }
    }
    //   m_appliance.app_mgr().async_get_application
    //     (m_app_id,
    //      boost::bind(&ApplicationInstaller::found_application, shared_from_this(), boost::placeholders::_1));
    // }

    // void ApplicationInstaller::found_application(std::shared_ptr<RegisteredApplication> app) {
    //   if ( app ) {
    //     auto shared(shared_from_this());
    //     app->async_when_built([shared] (boost::system::error_code ec, boost::filesystem::path &&p) {
    //         shared->application_has_version(ec, std::move(p));
    //       });
    //   } else {
    //     m_callback(std::make_error_code(application_not_found));
    //   }
    // }

    // void ApplicationInstaller::application_has_version(boost::system::error_code ec,
    //                                                    boost::filesystem::path &&p) {
    //   if ( ec ) {
    //     BOOST_LOG_TRIVIAL(error) << "Could not find application version: " << ec;
    //     m_callback(std::make_error_code(application_would_not_build));
    //   } else {
    //     BOOST_LOG_TRIVIAL(debug) << "Found application version " << p;

    //     m_appliance.container_mgr().async_launch_container
    //       (container_id(), p,
    //        boost::bind(&ApplicationInstaller::application_container_launched, shared_from_this(),
    //                    boost::placeholders::_1, boost::placeholders::_2));
    //   }
    // }

    void ApplicationInstaller::application_container_launched(std::error_code ec,
                                                              std::shared_ptr<container::AppInstanceMonitor> c ) {
      if ( ec ) {
        BOOST_LOG_TRIVIAL(error) << "Could not launch container: " << ec;
        m_callback(ec);
      } else {
        m_persona->async_install_application
          (m_app_id, boost::bind(&ApplicationInstaller::application_installation_registered,
                                 shared_from_this(), boost::placeholders::_1));
      }
    }

    void ApplicationInstaller::application_installation_registered(std::error_code ec) {
      m_callback(ec);
    }
  }
}
