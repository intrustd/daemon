#include <system_error>
#include <boost/asio.hpp>
#include <boost/process.hpp>
#include <boost/process/extend.hpp>
#include <boost/log/trivial.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include "../appliance.hpp"
#include "../unarchiver.hpp"
#include "manager.hpp"

namespace pt = boost::property_tree;
namespace fs = boost::filesystem;
namespace bp = boost::process;

namespace stork {
  namespace application {
    class NixBuild : public std::enable_shared_from_this<NixBuild> {
    public:
      NixBuild(boost::asio::io_service &svc, fs::path &&default_nix_path,
               fs::path &&build_output_path,
               fs::path &&log_dir_path, std::function<void(std::error_code)> &&h)
        : m_io_service(svc), m_handler(std::move(h)),
          m_default_nix_path(std::move(default_nix_path)),
          m_build_output_path(std::move(build_output_path)),
          m_log_dir_path(std::move(log_dir_path)) {
      }

      void start() {
        if ( !m_child.valid() ) {
          auto shared(shared_from_this());
          fs::path stdout_path(m_log_dir_path),
            stderr_path(m_log_dir_path);

          stdout_path /= "out.log";
          stderr_path /= "err.log";

          std::vector<std::string> args;

          const char *stork_env = getenv("STORK_NIX_BUNDLE");
          assert(stork_env); // TODO better error

          fs::path build_bundle(stork_env);
          build_bundle /= "build-bundle.nix";

          args.push_back(build_bundle.string());
          args.push_back("--argstr");
          args.push_back("stork-app-module");
          args.push_back(fs::absolute(m_default_nix_path).string());
          args.push_back("-o");
          args.push_back(m_build_output_path.string());

          m_child = bp::child(bp::exe="/run/current-system/sw/bin/nix-build",
                              bp::args=args,
                              bp::std_out > stdout_path,
                              bp::std_err > stderr_path,
                              bp::on_exit = [this, shared] ( int exit_code, const std::error_code &ec ) {
                                on_build_exit(exit_code, ec);
                              },
                              bp::extend::on_error = [this, shared] ( auto &exec, const std::error_code &ec ) {
                                on_build_exit(-1, ec);
                              }, m_io_service);
        }
      }

    private:
      void on_build_exit(int exit_code, const std::error_code &ec) {
        BOOST_LOG_TRIVIAL(debug) << "Build process exited";
        if ( ec ) {
          m_handler(ec);
        } else {
          if ( exit_code != 0 ) {
            BOOST_LOG_TRIVIAL(error) << "nix-build returned non-zero exit code: " << exit_code;
            m_handler(std::make_error_code(std::errc::bad_message));
          } else
            m_handler(ec);
        }
      }

      boost::asio::io_service &m_io_service;

      std::function<void(std::error_code)> m_handler;

      fs::path m_default_nix_path, m_build_output_path, m_log_dir_path;

      bp::child m_child;
    };

    RegisteredApplication::RegisteredApplication(boost::asio::io_service &svc,
                                                 Manager &mgr, const ApplicationManifest &mf,
                                                 std::shared_ptr<backend::IApplication> app)
      : m_io_service(svc), m_manager(mgr),
        m_app_update_strand(svc),
        m_manifest(mf),
        m_backend_app(app) {
      // TODO we should set an updating schedule if requested
      BOOST_LOG_TRIVIAL(debug) << "Registering application " << mf.identifier().canonical_url();
    }

    RegisteredApplication::~RegisteredApplication() {
    }

    void RegisteredApplication::schedule_update() {
      BOOST_LOG_TRIVIAL(info) << "Scheduling update for " << m_manifest.identifier().canonical_url();
      m_app_update_strand.post(boost::bind(&RegisteredApplication::start_update, shared_from_this()));
    }

    void RegisteredApplication::start_update() {
      auto shared(shared_from_this());

      BOOST_LOG_TRIVIAL(info) << "Checking for updates: " << m_manifest.identifier().canonical_url();
      BOOST_LOG_TRIVIAL(info) << "  - Using nix channel: " << m_manifest.nix_channel().raw();

      auto src(std::make_unique<uri::UriSource>(m_io_service, m_manifest.nix_channel()));
      auto channel_archive_path(m_backend_app->channel_archive_path());
      BOOST_LOG_TRIVIAL(info) << "start_update: 1";

      auto channel_archive_stream(std::make_shared<std::fstream>(channel_archive_path.string(), std::fstream::out));
      auto svr(std::make_shared<uri::UriSaver>(*channel_archive_stream, std::move(src)));
      BOOST_LOG_TRIVIAL(info) << "start_update: 2";

      svr->async_save([this, shared, svr, channel_archive_stream, channel_archive_path{std::move(channel_archive_path)}](uri::ErrorCode ec) {
          if ( ec ) {
            fs::path build_path(m_backend_app->application_channel_path());
            auto unzipper = std::make_shared<util::Unarchiver>(m_io_service, std::move(channel_archive_path), build_path);
            m_app_update_strand.async_restart();

            unzipper->async_unzip([this, shared, unzipper]( bool success ) {
                if ( success ) {
                  BOOST_LOG_TRIVIAL(debug) << "Successfully extracted archive";
                  schedule_forced_build();
                } else {
                  BOOST_LOG_TRIVIAL(error) << "Could not extract application archive";
                }
              });

          } else {
            m_app_update_strand.purge_all();
            BOOST_LOG_TRIVIAL(error) << "Error checking for updates: " << ec.description();
          }
        });

      BOOST_LOG_TRIVIAL(info) << "start_update: done";
    }

    void RegisteredApplication::schedule_forced_build() {
      BOOST_LOG_TRIVIAL(debug) << "Scheduling build of " << m_manifest.identifier().canonical_url();

      m_app_update_strand.post(boost::bind(&RegisteredApplication::do_build, shared_from_this()));
    }

    void RegisteredApplication::do_build() {
      auto shared(shared_from_this());

      BOOST_LOG_TRIVIAL(debug) << "Performing build of " << m_manifest.identifier().canonical_url();
      fs::path default_nix(m_backend_app->application_channel_path());
      default_nix /= "default.nix";

      fs::path build_path(m_backend_app->application_build_path());
      fs::path log_path(m_backend_app->application_log_path());

      std::string cur_time(boost::posix_time::to_iso_string_type<char>(boost::posix_time::second_clock::local_time()));
      log_path /= cur_time;

      BOOST_LOG_TRIVIAL(debug) << "Redirecting output to " << log_path;
      fs::create_directories(log_path);

      auto on_done = [this, shared, log_path] (std::error_code ec) {
        if ( ec ) {
          BOOST_LOG_TRIVIAL(debug) << "Could not build application: "
                                   << ec << ". Logs are in " << log_path;
          m_app_update_strand.purge_all();
        } else {
          BOOST_LOG_TRIVIAL(debug) << "Build done";
          m_app_update_strand.async_restart();
        }
      };
      auto builder(std::make_shared<NixBuild>(m_io_service, std::move(default_nix), std::move(build_path),
                                              std::move(log_path), std::move(on_done)));
      builder->start();
    }

    void RegisteredApplication::async_when_built(std::function<void(boost::system::error_code, boost::filesystem::path&&)> cb) {
      auto shared(shared_from_this());
      m_app_update_strand.post([this, shared, cb{std::move(cb)}] (stork::util::queue::reason r) {
          if ( r.normal() ) {
            fs::path build_path(m_backend_app->application_build_path());
            if ( fs::is_symlink(build_path) ) {
              // Read link and return
              boost::system::error_code ec;
              auto result_path(fs::read_symlink(build_path, ec));

              cb(ec, std::move(result_path));
              m_app_update_strand.async_restart();
            } else {
              schedule_forced_build();
              m_app_update_strand.post([this, cb{std::move(cb)}] (stork::util::queue::reason r) {
                  BOOST_LOG_TRIVIAL(debug) << "Application updated, calling callback";
                  if ( r.normal() ) {
                    this->async_when_built(std::move(cb));
                    m_app_update_strand.async_restart();
                  }
                });
              m_app_update_strand.async_restart();
            }
          }
        });
    }

    Manager::Manager(boost::asio::io_service &svc, appliance::Appliance &app)
      : m_io_service(svc), m_appliance(app),
        m_application_info_strand(svc) {

      m_application_info_strand.post(boost::bind(&Manager::start, this));
    }

    Manager::~Manager() {
    }

    void Manager::start() {
      BOOST_LOG_TRIVIAL(info) << "Application manager starting";
      auto apps = m_appliance.backend().list_installed_applications();
      for ( auto app_ptr: apps ) {
        auto input_stream(app_ptr->get_manifest_input_stream());
        ApplicationManifest this_app_mf(*input_stream);

        if ( this_app_mf.is_valid() ) {
          register_application(this_app_mf, app_ptr);
        } else
          BOOST_LOG_TRIVIAL(error) << "A registered application manifest is invalid";
      }
    }

    void Manager::async_register_application(ApplicationManifest mf, std::function<void(bool)> cb) {
      BOOST_LOG_TRIVIAL(debug) << "Registering application " << mf.identifier().canonical_url();

      m_application_info_strand.dispatch
        ([this, mf{std::move(mf)}, cb{std::move(cb)}] () {
          auto found = m_applications.find(mf.identifier());
          if ( found != m_applications.end() ) {
            BOOST_LOG_TRIVIAL(debug) << "Skipping registration of " << mf.identifier().canonical_url() << ", because it already exists. Attempting update instead";
            // TODO attempt update
            cb(true);
          } else {
            auto app_backend = m_appliance.backend().register_application(mf);
            register_application(std::move(mf), app_backend)->schedule_update();
            cb(true);
          }
        });
    }

    void Manager::async_list_applications(std::function<void(const ApplicationManifest &)> on_result,
                                          std::function<void()> on_done) {
      m_application_info_strand.dispatch
        ([this, on_result{std::move(on_result)}, on_done{std::move(on_done)}] () {
          for ( const auto &app: m_applications )
            on_result(app.second->manifest());

          on_done();
        });
    }

    void Manager::async_get_application(const ApplicationIdentifier &id,
                                        std::function<void(std::shared_ptr<RegisteredApplication>)> cb) {
      m_application_info_strand.dispatch
        ([this, cb{std::move(cb)}, id] () {
          auto found(m_applications.find(id));
          if ( found == m_applications.end() ) {
            m_io_service.post([cb{std::move(cb)}] () { cb(nullptr); });
          } else {
            auto found_app(found->second);
            m_io_service.post([cb{std::move(cb)}, found_app] () { cb(found_app); });
          }
        });
    }

    RegisteredApplication *Manager::register_application(ApplicationManifest mf, std::shared_ptr<backend::IApplication> app_backend) {
      auto ptr(std::make_shared<RegisteredApplication>(m_io_service, *this, std::move(mf), app_backend));
      auto *r = ptr.get();

      m_applications[mf.identifier()] = std::move(ptr);

      return r;
    }
  }
}
