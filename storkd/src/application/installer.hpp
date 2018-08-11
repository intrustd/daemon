#ifndef __stork_application_installer_HPP__
#define __stork_application_installer_HPP__

#include <memory>

#include "../appliance.hpp"
#include "../backend.hpp"
#include "manager.hpp"
#include "application.hpp"
#include "../container/container.hpp"

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

    private:
      void application_container_launched(std::error_code ec,
                                          std::shared_ptr<container::Container> c);

      inline container::ContainerId container_id() const {
        return container::ContainerId(m_persona_id, m_app_id);
      }

      appliance::Appliance &m_appliance;
      backend::PersonaId m_persona_id;
      ApplicationIdentifier m_app_id;
      std::function<void(std::error_code)> m_callback;
    };
  }
}
#endif
