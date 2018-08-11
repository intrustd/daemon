#include <boost/log/trivial.hpp>

#include "manager.hpp"
#include "container.hpp"
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

    fs::path Manager::container_work_dir(const ContainerId &cid) const {
      auto ret(run_directory());
      ret /= cid.persona_id().id();
      ret /= cid.app_id().domain();
      ret /= cid.app_id().app_id();
      return ret;
    }

    fs::path Manager::container_data_dir(const ContainerId &cid) const {
      auto ret(m_app.stork_directory());
      ret /= "app-data";
      ret /= cid.persona_id().id();
      ret /= cid.app_id().domain();
      ret /= cid.app_id().app_id();
      return ret;
    }

    void Manager::async_launch_container(const ContainerId &cid,
                                         const fs::path &image_path,
                                         std::function<void(std::error_code, std::shared_ptr<Container>)> cb) {
      m_containers_queue.post([this, cid, image_path, cb{std::move(cb)}] (auto reason) {
          if ( reason.normal() ) {

            auto found = m_containers.find(cid);
            if ( found == m_containers.end() ) {
              auto work_path(container_work_dir(cid));
              auto data_path(container_data_dir(cid));

              // TODO catch errors
              fs::create_directories(data_path);
              fs::create_directories(work_path);

              auto new_container(std::make_shared<Container>(*this, cid, image_path,
                                                             work_path, data_path));
              m_containers[cid] = new_container;
              m_containers_queue.async_restart();

              new_container->async_setup([this, cid, cb{std::move(cb)}, new_container] (std::error_code ec) {
                  if ( ec ) {
                    BOOST_LOG_TRIVIAL(error) << "Container could not be set up: " << ec;

                    m_containers_queue.post([this, cid] (auto reason) {
                        auto found = m_containers.find(cid);
                        if ( found != m_containers.end() )
                          m_containers.erase(found);
                        m_containers_queue.async_restart();
                      });

                    cb(ec, std::shared_ptr<Container>());
                  } else
                    cb(ec, new_container);
                });
            } else {
              auto container(found->second);
              m_containers_queue.async_restart();
              if ( container->image_path() == image_path ) {
                container->async_after_launch([cb{std::move(cb)}, container] (std::error_code ec, std::shared_ptr<ContainerMonitor> cm) {
                    if ( ec )
                      cb(ec, std::shared_ptr<Container>());
                    else
                      cb(std::error_code(), container);
                  });
              } else {
                cb(std::make_error_code(container_image_mismatch), std::shared_ptr<Container>());
              }
            }
          }
        });
    }

    void Manager::async_build_and_launch_container(const ContainerId &cid,
                                                   std::function<void(std::error_code, std::shared_ptr<Container>)> cb) {
      m_app.app_mgr().async_get_application
        (cid.app_id(),
         [this, cb{std::move(cb)}, cid](std::shared_ptr<application::RegisteredApplication> app) {
          if ( app ) {
            app->async_when_built
              ([this, cb{std::move(cb)}, cid{std::move(cid)}]
               (boost::system::error_code ec, boost::filesystem::path &&p) {
                if ( ec ) {
                  BOOST_LOG_TRIVIAL(error) << "Could not find application version: " << ec;
                  cb(std::make_error_code(application_would_not_build), std::shared_ptr<Container>());
                } else {
                  BOOST_LOG_TRIVIAL(debug) << "Found application version " << p;

                  m_app.container_mgr().async_launch_container
                    (cid, p,
                     [this, cb{std::move(cb)}] (std::error_code ec, std::shared_ptr<Container> c) {
                      cb(ec, c);
                    });
                }
              });
          } else
            cb(std::make_error_code(application_not_found), std::shared_ptr<Container>());
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
