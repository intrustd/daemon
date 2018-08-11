#ifndef __stork_appliance_HPP__
#define __stork_appliance_HPP__
#include <boost/filesystem.hpp>
#include <boost/asio.hpp>

#include <list>

#include "local_api.hpp"
#include "uri.hpp"
#include "backend.hpp"
#include "nix.hpp"
#include "application/manager.hpp"
#include "container/manager.hpp"

namespace stork {
  namespace appliance {
    class IFlockMembership;

    class Appliance {
    public:
      Appliance(boost::asio::io_service &svc, backend::IBackend &backend,
                nix::NixStore &nix_store,
                const boost::filesystem::path &stork_directory);
      ~Appliance();

      inline const boost::filesystem::path &stork_directory() const { return m_stork_directory; }
      boost::filesystem::path stork_name_path() const;
      boost::filesystem::path stork_local_api_socket_path() const;

      inline backend::IBackend &backend() { return m_backend; };
      inline application::Manager &app_mgr() { return m_app_mgr; };
      inline container::Manager &container_mgr() { return m_container_mgr; }
      inline const std::string &appliance_name() const { return m_appliance_name; }
      inline const boost::filesystem::path &stork_init_path() const { return m_stork_init_path; }

      void async_join_flock(uri::Uri swarm_uri,
                            std::function<void(uri::ErrorCode)> cb);
      void async_save_flocks();

      int run();

    private:
      void find_stork_init();
      void restore_state();

      void read_string_from_file(const boost::filesystem::path &path,
                                 std::string &destination) const;
      void write_string_to_file(const boost::filesystem::path &path,
                                const std::string &destination) const;
      void generate_new_name(std::string &name, std::size_t length=4) const;

      backend::IBackend &m_backend;
      nix::NixStore &m_nix_store;

      boost::filesystem::path m_stork_directory;

      std::string m_appliance_name;

      // IO Services
      boost::asio::io_service &m_io_service;
      std::list<std::thread> m_threads;

      // Various managers
      application::Manager m_app_mgr;
      container::Manager m_container_mgr;

      boost::asio::io_service::strand m_flock_management_strand;
      std::list< std::shared_ptr<IFlockMembership> > m_flocks;

      // Various configurations

      /**
       * Path to a suitable 'stork-init' program. Defaults to the current executable image.
       */
      boost::filesystem::path m_stork_init_path;
    };
  }
}

#endif
