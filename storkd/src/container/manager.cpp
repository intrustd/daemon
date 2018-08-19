#include <boost/log/trivial.hpp>

#include "manager.hpp"
#include "app_instance.hpp"
#include "../appliance.hpp"

namespace fs = boost::filesystem;

namespace stork {
  namespace container {
    Manager::Manager(boost::asio::io_service &svc,
                     appliance::Appliance &app)
      : m_service(svc), m_app(app),
        m_containers_queue(svc) {

      m_service.post(boost::bind(&Manager::init_run_directory, this));

    }

    fs::path Manager::run_directory() const {
      auto ret(m_app.stork_directory());
      ret /= "run";

      return ret;
    }

    fs::path Manager::app_instance_work_dir(const AppInstanceId &cid) const {
      auto ret(run_directory());
      ret /= cid.persona_id().id();
      ret /= cid.app_id().domain();
      ret /= cid.app_id().app_id();
      return ret;
    }

    fs::path Manager::app_instance_data_dir(const AppInstanceId &cid) const {
      auto ret(m_app.stork_directory());
      ret /= "app-data";
      ret /= cid.persona_id().id();
      ret /= cid.app_id().domain();
      ret /= cid.app_id().app_id();
      return ret;
    }

    bool Manager::persona_id_from_ip(const boost::asio::ip::address_v4 &a, backend::PersonaId &id) {
      boost::shared_lock l(m_reverse_ip_mutex);
      auto found(m_persona_ips.find(a));
      if ( found == m_persona_ips.end() ) return false;
      id = found->second;
      return true;
    }

    bool Manager::app_instance_id_from_ip(const boost::asio::ip::address_v4 &a, AppInstanceId &id) {
      boost::shared_lock l(m_reverse_ip_mutex);
      auto found(m_app_instance_ips.find(a));
      if ( found == m_app_instance_ips.end() ) return false;
      id = found->second;
      return true;
    }

    void Manager::async_launch_persona_container(const backend::PersonaId &pid,
                                                 std::function<void(std::error_code, std::shared_ptr<PersonaContainer>)> cb) {
      BOOST_LOG_TRIVIAL(info) << "Launching persona container";
      m_containers_queue.post([this, pid, cb{std::move(cb)}] (auto reason) {
          BOOST_LOG_TRIVIAL(info) << "Running containers fn";
          if ( reason.normal() ) {
            auto found(m_persona_containers.find(pid));
            if ( found == m_persona_containers.end() ) {
              auto new_container(std::make_shared<PersonaContainer>(m_service, m_app.bridge_controller(), pid));
              m_persona_containers[pid] = new_container;
              m_containers_queue.async_restart();

              new_container->async_after_launch
                ([cb{std::move(cb)}, this, pid, new_container]
                 (std::error_code ec) {
                  notify_persona_launches(pid, new_container->ip());
                  cb(ec, new_container);
                });
            } else {
              auto container(found->second);
              container->async_after_launch
                ([cb{std::move(cb)}, this, pid, container]
                 (std::error_code ec) {
                  notify_persona_launches(pid, container->ip());
                  cb(ec, container);
                });
              m_containers_queue.async_restart();
            }
          }
        });
    }

    void Manager::notify_persona_launches(const backend::PersonaId &pid,
                                          const boost::asio::ip::address_v4 &a) {
      boost::unique_lock l(m_reverse_ip_mutex);
      m_persona_ips.insert(std::make_pair(a, pid));
    }

    void Manager::async_launch_app_instance(const AppInstanceId &cid,
                                            const fs::path &image_path,
                                            std::function<void(std::error_code, std::shared_ptr<AppInstanceMonitor>)> cb) {
      m_containers_queue.post([this, cid, image_path, cb{std::move(cb)}] (auto reason) {
          if ( reason.normal() ) {

            auto found(m_app_instances.find(cid));
            if ( found == m_app_instances.end() ) {
              auto work_path(app_instance_work_dir(cid));
              auto data_path(app_instance_data_dir(cid));

              // TODO catch errors
              fs::create_directories(data_path);
              fs::create_directories(work_path);

              auto new_container(std::make_shared<AppInstance>(*this, cid, image_path,
                                                             work_path, data_path));
              m_app_instances[cid] = new_container;
              m_containers_queue.async_restart();

              new_container->async_setup([this, cid, cb{std::move(cb)}, new_container] (std::error_code ec) {
                  if ( ec ) {
                    BOOST_LOG_TRIVIAL(error) << "AppInstance could not be set up: " << ec;

                    m_containers_queue.post([this, cid] (auto reason) {
                        auto found = m_app_instances.find(cid);
                        if ( found != m_app_instances.end() )
                          m_app_instances.erase(found);
                        m_containers_queue.async_restart();
                      });

                    cb(ec, nullptr);
                  } else {
                    new_container->async_after_launch([this, cb{std::move(cb)}, new_container] (std::error_code ec, std::shared_ptr<AppInstanceMonitor> cm) {
                        notify_app_instance_launches(cm->owner().app_instance_id(),
                                                     cm->owner().ip_address());
                        cb(ec, cm);
                      });
                  }
                });
            } else {
              auto container(found->second);
              m_containers_queue.async_restart();
              if ( container->image_path() == image_path ) {
                container->async_after_launch([this, cb{std::move(cb)}, container] (std::error_code ec, std::shared_ptr<AppInstanceMonitor> cm) {
                    if ( ec )
                      cb(ec, nullptr);
                    else {
                      notify_app_instance_launches(cm->owner().app_instance_id(),
                                                   cm->owner().ip_address());
                      cb(std::error_code(), cm);
                    }
                  });
              } else {
                cb(std::make_error_code(container_image_mismatch), nullptr);
              }
            }
          }
        });
    }

    void Manager::notify_app_instance_launches(const AppInstanceId &id,
                                               const boost::asio::ip::address_v4 &a) {
      boost::unique_lock l(m_reverse_ip_mutex);
      m_app_instance_ips.insert(std::make_pair(a, id));
    }

    void Manager::async_build_and_launch_app_instance(const AppInstanceId &cid,
                                                      std::function<void(std::error_code, std::shared_ptr<AppInstanceMonitor>)> cb) {
      m_app.app_mgr().async_get_application
        (cid.app_id(),
         [this, cb{std::move(cb)}, cid](std::shared_ptr<application::RegisteredApplication> app) {
          if ( app ) {
            app->async_when_built
              ([this, cb{std::move(cb)}, cid{std::move(cid)}]
               (boost::system::error_code ec, boost::filesystem::path &&p) {
                if ( ec ) {
                  BOOST_LOG_TRIVIAL(error) << "Could not find application version: " << ec;
                  cb(std::make_error_code(application_would_not_build), nullptr);
                } else {
                  BOOST_LOG_TRIVIAL(debug) << "Found application version " << p;

                  m_app.container_mgr().async_launch_app_instance
                    (cid, p,
                     [this, cb{std::move(cb)}] (std::error_code ec, std::shared_ptr<AppInstanceMonitor> c) {
                      cb(ec, c);
                    });
                }
              });
          } else
            cb(std::make_error_code(application_not_found), nullptr);
        });
    }

    void Manager::init_run_directory() {
      auto run_path(run_directory());

      fs::create_directories(run_path);

      // TODO purge everything in run path
    }

    class ManagerErrorCategory : public std::error_category {
    public:
      virtual const char *name() const noexcept {
        return "stork::container::ManagerErrorCategory";
      };

      virtual std::string message(int value) const override {
        switch ( Manager::errc_t(value) ) {
        case Manager::container_image_mismatch:
          return "Container image mismatch";
        case Manager::application_not_found:
          return "Application not found";
        case Manager::application_would_not_build:
          return "Application would not build";
        default:
          return "Unknown error";
        }
      };
    };

    const std::error_category &Manager::error_category() {
      static ManagerErrorCategory ec;
      return ec;
    }
  }
}
