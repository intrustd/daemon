#ifndef __stork_container_manager_HPP__
#define __stork_container_manager_HPP__

#include <system_error>
#include <boost/asio.hpp>

#include "../queue.hpp"
#include "container.hpp"

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

      // Launches the requested container
      //
      // This means that a namespace is connected and a root path
      // constructed (and mounted within the namespace)
      //
      // Processes can be launched inside the container
      void async_launch_container(const ContainerId &cid,
                                  const boost::filesystem::path &image_path,
                                  std::function<void(std::error_code, std::shared_ptr<Container>)> cb);

      // Builds and launches the container if it is not running
      void async_build_and_launch_container(const ContainerId &cid,
                                            std::function<void(std::error_code, std::shared_ptr<Container>)> cb);

      inline boost::asio::io_service &service() const { return m_service; }
      inline appliance::Appliance &appliance() const { return m_app; }
      boost::filesystem::path run_directory() const;

      static const std::error_category &error_category();

    private:
      boost::filesystem::path container_work_dir(const ContainerId &cid) const;
      boost::filesystem::path container_data_dir(const ContainerId &cid) const;

      void init_run_directory();

      boost::asio::io_service &m_service;
      appliance::Appliance    &m_app;

      stork::util::queue m_containers_queue;
      std::unordered_map<ContainerId, std::shared_ptr<Container> > m_containers;
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
