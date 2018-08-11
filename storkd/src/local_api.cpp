#include <boost/filesystem.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/log/trivial.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <memory>

#include <arpa/inet.h>

#include "application/application.hpp"
#include "application/installer.hpp"
#include "local_api.hpp"
#include "local_proto.hpp"
#include "appliance.hpp"
#include "uri.hpp"

namespace fs = boost::filesystem;
namespace local = boost::asio::local;
namespace pt = boost::property_tree;

namespace stork {
  namespace appliance {
    class LocalApiSession : public std::enable_shared_from_this<LocalApiSession>,
                            public proto::local::ICommandDispatch {
    public:
      LocalApiSession(Appliance &appliance, boost::asio::io_service &svc,
                      local::stream_protocol::socket s)
        : m_conn_no(m_next_conn_no++),
          m_appliance(appliance),
          m_service(svc),
          m_socket(std::move(s)),
          m_frame_sender(m_socket) {
        BOOST_LOG_TRIVIAL(debug) << "[LocalApi] Connection number " << m_conn_no;
      }

      virtual ~LocalApiSession() {
        BOOST_LOG_TRIVIAL(debug) << "[LocalApi] Connection number " << m_conn_no << " closes";
      }

      void serve() {
        auto shared(shared_from_this());
        boost::asio::async_read
          (m_socket, boost::asio::buffer(&m_request_size, sizeof(m_request_size)),
           [this, shared](boost::system::error_code ec, std::size_t len) {
            if ( ec || len < 2 )
              finish_session_with_error(ec);
            else {
              m_request_size = ntohs(m_request_size);
              m_request_buffer.resize(m_request_size);

              boost::asio::async_read
                (m_socket, boost::asio::buffer(m_request_buffer),
                 [this, shared](boost::system::error_code ec, std::size_t len) {
                  if ( ec || len < m_request_size )
                    finish_session_with_error(ec);
                  else {
                    BOOST_LOG_TRIVIAL(debug) << "[LocalApi] [Connection " << m_conn_no << "] Received buffer of length " << m_request_size;

                    std::stringstream parse_stream(m_request_buffer);
                    proto::ProtoParser parser(parse_stream);

                    std::unique_ptr<proto::local::Command> parsedCommand;
                    try {
                      parsedCommand = proto::local::Command::read(parser);
                    } catch ( proto::ProtoParseException &e) {
                    }

                    if ( !parsedCommand ) {
                      unrecognized_command_error();
                    } else {
                      parsedCommand->dispatch(*this);
                    }
                  }
                });
            }
          });
      }

      virtual void new_persona(const proto::local::NewPersonaCommand &cmd) {
        BOOST_LOG_TRIVIAL(info) << "Going to make persona with name "
                                << cmd.profile().full_name();

        std::shared_ptr<backend::IPersona> persona(m_appliance.backend().new_persona(cmd.profile()));

        proto::local::NewPersonaResponse response(persona->persona_id());
        write_response(response);
      }

      virtual void install_application(const proto::local::InstallApplicationCommand &cmd) {
        BOOST_LOG_TRIVIAL(info) << "Going to install application " << cmd.app_id().canonical_url()
                                << " for persona " << cmd.persona_id().id();

        auto shared(shared_from_this());
        auto on_finished = [this, shared] (std::error_code ec) {
          if ( ec ) {
            BOOST_LOG_TRIVIAL(error) << "Error installing app: " << ec;
            proto::local::Response r(proto::local::Response::Codes::unknown_error);
            write_response(r);
          } else {
            proto::local::Response r(proto::local::Response::Codes::success);
            write_response(r);
          }
        };

        auto installer(std::make_shared<application::ApplicationInstaller>
                       (m_appliance, cmd.persona_id(), cmd.app_id(),
                        std::move(on_finished)));
        installer->async_install();
      }

      virtual void register_app(const proto::local::RegisterApplicationCommand &cmd) {
        auto shared(shared_from_this());

        BOOST_LOG_TRIVIAL(info) << "Going to register application with manifest "
                                << cmd.application_manifest_url();


        stork::uri::Uri uri(cmd.application_manifest_url());

        if ( !uri.is_valid() ) {
          proto::local::Response r(proto::local::Response::Codes::invalid_uri);
          write_response(r);
        } else {
          auto source = std::make_unique<stork::uri::UriSource>(m_service, uri);

          if ( source->is_valid() ) {
            auto fetcher = std::make_shared<stork::uri::UriFetcher>(std::move(source), 64 * 1024);
            fetcher->async_fetch
              ([this, shared, fetcher, uri](stork::uri::ErrorCode ec,
                              const std::string &app_data) {
                if ( ec ) {
                  std::stringstream app_data_stream(app_data);
                  application::ApplicationManifest mf(app_data_stream);

                  if ( mf.is_valid() ) {
                    m_appliance.app_mgr().async_register_application
                      (std::move(mf), [this, shared, fetcher, uri](bool success) {
                        if (success) {
                          proto::local::Response r(proto::local::Response::Codes::success);
                          write_response(r);
                        } else {
                          proto::local::Response r(proto::local::Response::Codes::unavailable);
                          write_response(r);
                        }
                      });
                  } else {
                    proto::local::Response r(proto::local::Response::Codes::invalid_manifest);
                    write_response(r);
                  }
                } else {
                  switch ( ec.code() ) {
                  case stork::uri::not_found: {
                      proto::local::Response r(proto::local::Response::Codes::manifest_not_found);
                      write_response(r);
                  }
                    break;
                  case stork::uri::unavailable: {
                    proto::local::Response r(proto::local::Response::Codes::unavailable);
                    write_response(r);
                  }
                    break;
                  default: {
                    proto::local::Response r(proto::local::Response::Codes::unknown_error);
                    write_response(r);
                  }
                    break;
                  }
                }
            });
          } else {
            proto::local::Response r(proto::local::Response::Codes::unknown_uri_scheme);
            write_response(r);
          }
        }
      }

      virtual void list_applications(const proto::local::ListApplicationsCommand &cmd) {
        auto shared(shared_from_this());

        m_appliance.app_mgr().async_list_applications
          ([this, shared](const application::ApplicationManifest &mf) {
              proto::local::ApplicationResultResponse r(mf.identifier(), mf.name());
              write_response(r);
            },
            [this, shared]() {
              proto::local::ApplicationResultResponse r;
              write_response(r);
            });
      }

      virtual void join_flock(const proto::local::JoinFlockCommand &cmd) {
        auto shared(shared_from_this());
        BOOST_LOG_TRIVIAL(info) << "[LocalApi] [Connection " << m_conn_no << "] Request to join flock: "
                                << cmd.flock_uri().raw();

        m_appliance.async_join_flock
          (cmd.flock_uri(),
           [this, shared](uri::ErrorCode ec) {
            if ( ec ) {
              m_appliance.async_save_flocks();

              proto::local::Response r(proto::local::Response::Codes::success);
              write_response(r);
            } else {
              switch ( ec.code() ) {
              case stork::uri::unknown_scheme:
              case stork::uri::invalid_source: {
                proto::local::Response r(proto::local::Response::Codes::unknown_uri_scheme);
                write_response(r);
              }
              default: {
                proto::local::Response r(proto::local::Response::Codes::unknown_error);
                write_response(r);
              }
              }
            }
          });
      }

    private:
      void unrecognized_command_error() {
        BOOST_LOG_TRIVIAL(error) << "[LocalApi] [Connection " << m_conn_no << "] Receive unrecognized command";
      }
      void finish_session_with_error(boost::system::error_code ec) {
        BOOST_LOG_TRIVIAL(error) << "[LocalApi] [Connection " << m_conn_no << "] Error " << ec;
      }

      void write_response(proto::local::Response &response) {
        auto shared(shared_from_this());
        m_frame_sender.async_write(response,
                                   [this, shared]
                                   (boost::system::error_code ec) {
                                     if ( ec ) {
                                       BOOST_LOG_TRIVIAL(error) << "Error sending response: " << ec;
                                     } else
                                       m_service.post(boost::bind(&LocalApiSession::serve, shared_from_this()));
                                   });
      }

      static std::uint64_t m_next_conn_no;

      std::uint64_t m_conn_no;

      std::uint16_t m_request_size;
      std::string m_request_buffer;

      Appliance &m_appliance;
      boost::asio::io_service &m_service;
      local::stream_protocol::socket m_socket;

      proto::FramedSender<std::uint16_t, local::stream_protocol::socket> m_frame_sender;
    };

    std::uint64_t LocalApiSession::m_next_conn_no = 0;

    LocalApi::LocalApi(Appliance &app, boost::asio::io_service &service)
      : m_appliance(app), m_service(service), m_acceptor(service)
    {
      start();
    }

    LocalApi::~LocalApi() {
    }

    void LocalApi::start() {
      fs::path socketPath(appliance().stork_local_api_socket_path());
      fs::file_status socketStatus(fs::status(socketPath));

      if ( socketStatus.type() != fs::file_type::file_not_found &&
           socketStatus.type() != fs::file_type::socket_file )
        throw std::runtime_error("Local API socket already exists, and is not a socket");

      if ( socketStatus.type() == fs::file_type::socket_file )
        fs::remove(socketPath);

      local::stream_protocol::endpoint endpoint(socketPath.string());
      m_acceptor.open(endpoint.protocol());
      m_acceptor.bind(endpoint);
      m_acceptor.listen();

      accept();
    }

    void LocalApi::accept() {
      m_acceptor.async_accept
        ([this] ( boost::system::error_code ec, local::stream_protocol::socket socket) {
          if (!ec) {
            std::make_shared<LocalApiSession>(appliance(), m_service, std::move(socket))->serve();
            accept();
          } else {
            BOOST_LOG_TRIVIAL(error) << "Local API accept error: " << ec;
          }
        });
    }
  }
}
