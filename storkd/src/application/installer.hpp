#ifndef __stork_application_installer_HPP__
#define __stork_application_installer_HPP__

#include <memory>

#include "../appliance.hpp"
#include "../backend.hpp"
#include "manager.hpp"
#include "application.hpp"
#include "../container/app_instance.hpp"

namespace stork {
  namespace application {
    class ApplicationInstaller : public std::enable_shared_from_this<ApplicationInstaller> {
    public:
      ApplicationInstaller(appliance::Appliance &app, const backend::PersonaId &persona,
                           const ApplicationIdentifier &app_id,
                           std::function<void(std::error_code)> &&cb);
      ~ApplicationInstaller();

      void async_install();

      static const std::error_category &error_category();

      inline container::AppInstanceId app_instance_id() const {
        return container::AppInstanceId(m_persona_id, m_app_id);
      }

    private:
      void got_persona(std::shared_ptr<backend::IPersona> p);
      void application_container_launched(std::error_code ec,
                                          std::shared_ptr<container::AppInstanceMonitor> c);
      void application_installation_registered(std::error_code ec);
      appliance::Appliance &m_appliance;
      backend::PersonaId m_persona_id;
      ApplicationIdentifier m_app_id;

      std::shared_ptr<backend::IPersona> m_persona;

      std::function<void(std::error_code)> m_callback;
    };
  }
}
#endif
