#include <boost/bind.hpp>
#include <boost/log/trivial.hpp>
#include <iostream>

#include "../uri_endpoint.hpp"
#include "../queue.hpp"
#include "proto.hpp"
#include "manager.hpp"

namespace ip = boost::asio::ip;

constexpr int FLOCK_PING_FREQUENCY = 5; // Ping every 5 seconds

namespace stork {
  namespace flock {
    namespace flockd {
      class IFlockServer {
      public:
        virtual ~IFlockServer() {};
      };

      template<typename Socket>
      class socket_closer {
      public:
      };

      template<>
      class socket_closer<boost::asio::ip::tcp::socket> {
      public:
        static void close_socket(boost::asio::ip::tcp::socket &s) {
          s.cancel();
          s.close();
        };
      };

      template<>
      class socket_closer<stork::websocket<boost::asio::ip::tcp>::socket> {
      public:
        static void close_socket(typename stork::websocket<boost::asio::ip::tcp>::socket &s) {
          s.next_layer().cancel();
          s.close(boost::beast::websocket::normal);
        }
      };

      template<typename Socket>
      class FlockSession : public std::enable_shared_from_this< FlockSession<Socket> >,
                           public proto::flock::ICommandDispatch,
                           public stork::flock::ILiveDevice {
      public:
        FlockSession(Manager &mgr, Socket s)
          : m_manager(mgr), m_socket(std::move(s)),
            m_frame_sender(m_socket, 4 * 1024),
            m_frame_reader(m_socket, 4 * 1024),
            m_queue(mgr.service()), m_exited(false),
            m_ping_timer(mgr.service()),
            m_session_state(session_appliance_or_client) {
        }

        virtual ~FlockSession() {
          // TODO schedule unregistering this device
          BOOST_LOG_TRIVIAL(debug) << "Flock session done";
        }

        virtual void register_device(const proto::flock::RegisterDeviceCommand &cmd) {
          auto shared(this->shared_from_this());
          BOOST_LOG_TRIVIAL(info) << "Registering device " << cmd.name();

          if ( m_session_state != session_appliance_or_client ) {
            BOOST_LOG_TRIVIAL(error) << "Received register device while not initializing";
            proto::flock::Response r(proto::flock::Response::Codes::invalid_state);
            write_response(r);
            finish_connection_with_error();
          } else {
            if ( cmd.proto_version() > 1 )
              BOOST_LOG_TRIVIAL(warning) << "Device registering claiming to speak newer protocol";

            std::string login_token("This is a token");
            m_device_info = std::make_shared<RegisteredDeviceInfo>
              (cmd.name(), login_token, boost::chrono::seconds(30),
               this->shared_from_this());

            proto::flock::RegisterDeviceResponse response_on_success(1, login_token, boost::chrono::seconds(30));

            m_manager.backend().async_register_device
              (m_device_info,
               [this, shared, response_on_success{std::move(response_on_success)}]
               (IBackend::error_code ec) {
                if ( ec ) {
                  proto::flock::Response r(proto::flock::Response::Codes::unknown_error); // TODO better errors
                  write_response(r);
                  finish_connection_with_error();
                } else {
                  m_session_state = session_appliance;

                  write_response(response_on_success, false);

                  // Start timer
                  start_ping_timer();
                }
              });
          }
        }

        virtual void login_to_device(const proto::flock::LoginToDeviceCommand &cmd) {
          auto shared(this->shared_from_this());
          BOOST_LOG_TRIVIAL(info) << "Attempting login to device " << cmd.name();

          if ( cmd.proto_version() > 1 )
            BOOST_LOG_TRIVIAL(warning) << "Login claiming to speak newer protocol";

          if ( m_session_state == session_appliance_or_client ||
               m_session_state == session_authenticating_client ) {
            if ( cmd.has_credentials() ) {
              BOOST_LOG_TRIVIAL(info) << "Attempting to log in with credentials";

              backend::LoginCredentials creds(cmd.credentials());
              m_manager.backend().async_find_device
                (cmd.name(),
                 [this, shared, creds{std::move(creds)}]
                 (std::shared_ptr<RegisteredDeviceInfo> rdi) mutable {
                  if ( !rdi ) {
                    proto::flock::Response r(proto::flock::Response::Codes::no_such_device);
                    write_response(r, false);
                  } else {
                    rdi->live_device()->send_login_to_device
                      (std::move(creds),
                       [this, shared, rdi]
                       ( boost::system::error_code ec, proto::flock::Response::ResponseCode rc, const std::string &token) {
                        if ( ec )
                          BOOST_LOG_TRIVIAL(error) << "Could not process login: " << ec;

                        if ( rc == proto::flock::Response::Codes::success ) {
                          // TODO set timeout after which to close connection
                          m_session_state = session_dialing_client;
                          m_dialing_device = rdi;
                          m_dialing_token = token;
                        }
                        write_response(proto::flock::Response(rc));
                      });
                  }
                });
            } else {
              m_session_state = session_authenticating_client;
              m_manager.backend().async_find_device
                (cmd.name(),
                 [this, shared](std::shared_ptr<RegisteredDeviceInfo> rdi) {
                  if ( !rdi ) {
                    proto::flock::Response r(proto::flock::Response::Codes::no_such_device);
                    write_response(r);
                  } else {
                    rdi->live_device()->gather_personas([this, shared](boost::system::error_code ec, stork::proto::flock::LoginToDeviceResponse &&rsp) {
                        write_response(rsp, rsp.status() != proto::flock::Response::Codes::success);
                      });
                  }
                });
            }
          } else {
            BOOST_LOG_TRIVIAL(error) << "Received login request while not initializing";
            proto::flock::Response r(proto::flock::Response::Codes::invalid_state);
            write_response(r);
            finish_connection_with_error();
          }
        }

        virtual void start_login(const proto::flock::StartLoginCommand &cmd) {
          BOOST_LOG_TRIVIAL(error) << "Start login command not valid in flockd";
          finish_connection_with_error();
        }

        virtual void ping(const proto::flock::PingCommand &cmd) {
          proto::flock::Response r(proto::flock::Response::Codes::success);
          write_response(r);
        }

        virtual void dial_session(const proto::flock::DialSessionCommand &cmd) {
          if ( m_session_state != session_dialing_client ) {
            BOOST_LOG_TRIVIAL(error) << "Received dial session when no dial in progress";
            write_response(proto::flock::Response(proto::flock::Response::Codes::invalid_state));
            finish_connection_with_error();
          } else {
            std::shared_ptr<RegisteredDeviceInfo> device(m_dialing_device.lock());
            if ( !device ) {
              BOOST_LOG_TRIVIAL(error) << "Dial cannot continue because remote appliance disconnected";
              write_response(proto::flock::Response(proto::flock::Response::Codes::device_malfunction));
              finish_connection_with_error();
            } else if ( !cmd.valid() ) {
              write_response(proto::flock::Response(proto::flock::Response::Codes::invalid_request));
            } else {
              proto::flock::DialSessionCommand appliance_cmd(m_dialing_token, cmd.type(), cmd.data());
              BOOST_LOG_TRIVIAL(info) << "Received dial session " << cmd.type() << " " << cmd.data();

              bool needs_response = cmd.needs_response();

              auto shared(this->shared_from_this());
              device->live_device()->
                send_dial(std::move(appliance_cmd),
                          [shared, needs_response] (boost::system::error_code ec, const proto::flock::Response &r) {
                            // TODO this can be called while we're running othe operations?
                            if ( ec ) {
                              if ( needs_response )
                                shared->write_response(proto::flock::Response(proto::flock::Response::Codes::unknown_error), false);
                              shared->finish_connection_with_error();
                            } else if ( needs_response ) {
                              // Read the response from the remote server
                              shared->write_response(r);
                            }
                          });

              if ( !needs_response ) {
                // This command does not generate a response
                m_manager.service().post([shared] () { shared->start_serve(); });
              }
            }
          }
        }

        virtual void gather_personas(std::function<void(boost::system::error_code, stork::proto::flock::LoginToDeviceResponse &&)> cb) {
          auto shared(this->shared_from_this());
          const auto device_info(m_device_info);

          BOOST_LOG_TRIVIAL(debug) << "Gather personas";

          m_queue.dispatch([this, shared, device_info, cb{std::move(cb)}] (stork::util::queue::reason r) {
              if ( r.will_not_run() ) {
                auto r(proto::flock::LoginToDeviceResponse::device_malfunction());
                cb(boost::system::error_code(), std::move(r));
              } else {
                proto::flock::StartLoginCommand cmd;
                BOOST_LOG_TRIVIAL(debug) << "Starting login with device " << device_info->name();
                m_frame_sender.async_write
                  (cmd, [this, shared, device_info, cb{std::move(cb)}](boost::system::error_code ec) {
                    if ( ec ) {
                      BOOST_LOG_TRIVIAL(error) << "Could not start login with device: " << device_info->name();
                      finish_connection_with_error();
                    } else {
                      stream_login_response(std::move(cb));
                    }
                  });
              }
            });
        }

        virtual void send_login_to_device(backend::LoginCredentials &&creds,
                                          std::function<void(boost::system::error_code, proto::flock::Response::ResponseCode,
                                                             const std::string& token)> cb) override {
          auto shared(this->shared_from_this());

          m_queue.dispatch([this, shared, creds{std::move(creds)}, cb{std::move(cb)}]
                           ( stork::util::queue::reason r ) mutable {
              if ( r.will_not_run() ) {
                cb(boost::system::error_code(), proto::flock::Response::Codes::device_malfunction, "");
              } else {
                proto::flock::LoginToDeviceCommand cmd(1, m_device_info->name());
                cmd.set_credentials(std::move(creds));

                shared->m_frame_sender.async_write
                  (cmd, [this, shared, cb{std::move(cb)}]
                   (boost::system::error_code ec) {
                    if ( ec )
                      finish_connection_with_error();
                    else {
                      shared->m_frame_reader.async_read_frame
                        ([this, shared, cb{std::move(cb)}]
                         (boost::system::error_code ec) {
                          if ( ec ) {
                            BOOST_LOG_TRIVIAL(error) << "Could not read login response";
                            cb(ec, proto::flock::Response::Codes::unknown_error, "");
                            shared->finish_connection_with_error();
                          } else {
                            // TODO any of these could throw exceptions...
                            auto r(shared->m_frame_reader.template read<proto::flock::LoginToDeviceResponse>());
                            if ( r.status() == proto::flock::Response::Codes::success ) {
                              const auto &ps(r.profile_properties());
                              auto token_p(std::find_if(ps.begin(), ps.end(), [] ( const auto &p ) {
                                    return p.first == "token";
                                  }));
                              if ( token_p == ps.end() ) {
                                BOOST_LOG_TRIVIAL(error) << "No token property in login response";
                                cb(ec, proto::flock::Response::Codes::device_malfunction, "");
                                shared->finish_connection_with_error();
                              } else {
                                cb(ec, proto::flock::Response::Codes::success, token_p->second); // TODO
                                shared->m_queue.async_restart();
                              }
                            } else if ( r.status() == proto::flock::Response::Codes::invalid_credentials ) {
                              cb(ec, proto::flock::Response::Codes::invalid_credentials, "");
                              shared->m_queue.async_restart();
                            } else {
                              BOOST_LOG_TRIVIAL(debug) << "Invalid response to login request: " << r.status_string();
                              cb(ec, proto::flock::Response::Codes::unknown_error, "");
                              shared->finish_connection_with_error();
                            }
                          }
                        });
                    }
                  });
              }
            });
        }

        virtual void send_dial(proto::flock::DialSessionCommand &&cmd,
                               std::function<void(boost::system::error_code, const proto::flock::Response &)> cb) {
          auto shared(this->shared_from_this());
          m_queue.dispatch([shared, cmd{std::move(cmd)}, cb{std::move(cb)}] ( stork::util::queue::reason r ) {
              if ( r.normal() ) {
                bool needs_response = cmd.needs_response();
                shared->m_frame_sender.async_write
                  (cmd, [shared, cb{std::move(cb)}, needs_response] ( boost::system::error_code ec ) {
                    if ( ec )
                      shared->finish_connection_with_error();

                    // Read response if necessary
                    if ( needs_response ) {
                      shared->m_frame_reader.async_read_frame
                        ([shared, cb{std::move(cb)}]
                         (boost::system::error_code ec) {
                          if ( ec ) {
                            BOOST_LOG_TRIVIAL(error) << "Could not read dial response";
                            cb(ec, proto::flock::Response(proto::flock::Response::Codes::unknown_error));
                            shared->finish_connection_with_error();
                          } else {
                            auto r(shared->m_frame_reader.template read<proto::flock::DialResponse>());
                            cb(ec, r);
                          }
                        });
                    } else {
                      cb(ec, proto::flock::Response(proto::flock::Response::Codes::success));
                      shared->m_queue.async_restart();
                    }
                  });
              }
            });
        }

        void stream_login_response(std::function<void(boost::system::error_code, stork::proto::flock::LoginToDeviceResponse &&)> cb) {
          auto shared(this->shared_from_this());
          const auto device_info(m_device_info);

          m_frame_reader.async_read_frame
            ([this, shared, device_info, cb{std::move(cb)}](boost::system::error_code ec) {
              if ( ec ) {
                BOOST_LOG_TRIVIAL(error) << "Could not read from device after starting login: " << device_info->name();
                cb(ec, proto::flock::LoginToDeviceResponse::unknown_error());
                finish_connection_with_error();
              } else {
                try {
                  auto r(this->m_frame_reader.template read<proto::flock::LoginToDeviceResponse>());
                  cb(boost::system::error_code(), std::move(r));
                  if ( r.status() == proto::flock::Response::Codes::success )
                    stream_login_response(std::move(cb));

                  // TODO if the error returned is fatal, close this connection
                  else
                    m_queue.async_restart();
                } catch (proto::ProtoParseException &p) {
                  BOOST_LOG_TRIVIAL(error) << "Could not parse response after starting login: " << device_info->name();
                  finish_connection_with_error();
                }
              }
            });
        }

        void start_serve() {
          auto shared(this->shared_from_this());

          m_frame_reader.async_read_frame
            ([this, shared](boost::system::error_code ec) {
                respond_to_request(ec);
            });
        }

      private:
        void respond_to_request(boost::system::error_code ec) {
          if ( ec ) {
            BOOST_LOG_TRIVIAL(error) << "Error reading request: " << ec;
          } else {
            const std::string &frame(m_frame_reader.cur_frame());
            std::stringstream frame_stream(frame);
            proto::ProtoParser frame_parser(frame_stream);

            try {
              auto command(proto::flock::Command::read(frame_parser));

              if ( command ) {
                command->dispatch(*this);
              } else {
                BOOST_LOG_TRIVIAL(error) << "Invalid request";
              }
            } catch (proto::ProtoParseException &e) {
              BOOST_LOG_TRIVIAL(error) << "Failed to parse request: " << e.what();
              write_response(proto::flock::Response(proto::flock::Response::Codes::invalid_request));
            }
          }
        }

        void write_response(const proto::flock::Response &r, bool continue_service=true) {
          auto shared(this->shared_from_this());
          m_frame_sender.async_write
            (r, [this, shared, continue_service](boost::system::error_code ec) {
              if ( ec ) {
                BOOST_LOG_TRIVIAL(error) << "Error while writing response: " << ec;
                finish_connection_with_error();
              } else {
                if ( continue_service )
                  m_manager.service().post([this, shared] () { this->start_serve(); });
              }
            });
        }

        void start_ping_timer() {
          auto shared(this->shared_from_this());

          boost::system::error_code ec;
          m_ping_timer.expires_from_now(boost::posix_time::seconds(FLOCK_PING_FREQUENCY), ec);
          if ( ec ) BOOST_LOG_TRIVIAL(error) << "Could not set ping timer: " << ec;
          else {
            std::weak_ptr weak_this(shared);
            m_ping_timer.async_wait([weak_this] (boost::system::error_code ec) {
                if ( ec ) BOOST_LOG_TRIVIAL(error) << "Could not wait for timer: " << ec;
                else {
                  auto session(weak_this.lock());
                  if ( session )
                    session->queue_ping();
                }
              });
          }
        }

        void queue_ping() {
          std::weak_ptr weak_this(this->shared_from_this());
          m_queue.dispatch([weak_this] (stork::util::queue::reason r) {
              if ( r.normal() ) {
                auto shared(weak_this.lock());
                if ( shared ) {
                  proto::flock::PingCommand cmd;
                  shared->m_frame_sender.async_write(cmd, [shared] (boost::system::error_code ec) {
                      BOOST_LOG_TRIVIAL(debug) << "Sending ping";
                      if ( ec ) shared->finish_connection_with_error();
                      else {
                        shared->m_frame_reader.async_read_frame([shared] (boost::system::error_code ec) {
                            if ( ec ) shared->finish_connection_with_error();
                            else {
                              const std::string &frame(shared->m_frame_reader.cur_frame());
                              std::stringstream frame_stream(frame);
                              proto::ProtoParser frame_parser(frame_stream);

                              proto::flock::Response response(frame_parser);
                              if ( response.is_error() ) {
                                BOOST_LOG_TRIVIAL(error) << "Got error response from ping: " << response.status_string();
                                shared->finish_connection_with_error();
                              } else {
                                BOOST_LOG_TRIVIAL(debug) << "Ping successful";
                                shared->m_queue.async_restart();
                                shared->start_ping_timer();
                              }
                            }
                          });
                      }
                    });
                }
              }
            });
        }

        void finish_connection_with_error() {
          boost::unique_lock l(m_cleanup_lock);

          socket_closer<Socket>::close_socket(m_socket);

          if ( !m_exited ) {
            BOOST_LOG_TRIVIAL(error) << "Closing connection due to error";

            if ( m_device_info ) {
              m_device_info->connection_closing();
              m_device_info.reset();
            }

            m_queue.purge_all();

            m_exited = true;
          }
        }

        Manager &m_manager;
        Socket m_socket;

        proto::FramedSender<std::uint16_t, Socket> m_frame_sender;
        proto::FramedReader<std::uint16_t, Socket> m_frame_reader;

        std::shared_ptr<RegisteredDeviceInfo> m_device_info;

        stork::util::queue m_queue;

        boost::mutex m_cleanup_lock;
        bool m_exited;

        boost::asio::deadline_timer m_ping_timer;

        enum {
          session_appliance_or_client,
          session_appliance,
          session_authenticating_client,
          session_dialing_client
        } m_session_state;

        std::weak_ptr<RegisteredDeviceInfo> m_dialing_device;
        std::string m_dialing_token;
      };

      template<typename Acceptor>
      class FlockServer : public IFlockServer {
      public:
        FlockServer(Manager &mgr, const typename Acceptor::endpoint_type &iface)
          : m_manager(mgr), m_acceptor(mgr.service(), iface) {
          BOOST_LOG_TRIVIAL(debug) << "Starting on " << iface;

          serve();
        }

        virtual ~FlockServer() {};

      private:
        void serve() {
          m_acceptor.async_accept([this] (boost::system::error_code ec,
                                          typename Acceptor::protocol_type::socket peer) {
                                    accept_connection(ec, std::move(peer));
                                  });
        }

        void accept_connection(boost::system::error_code ec,
                               typename Acceptor::protocol_type::socket peer) {
          if ( ec ) {
            BOOST_LOG_TRIVIAL(error) << "Error accepting connection on socket " << m_acceptor.local_endpoint() << ": " << ec;
          } else {
            auto session(std::make_shared< FlockSession< typename Acceptor::protocol_type::socket > >(m_manager, std::move(peer)));
            session->start_serve();
            serve();
          }
        }

        Manager &m_manager;
        Acceptor m_acceptor;
      };

      Manager::Manager(boost::asio::io_service &svc, const Configuration &conf, IBackend &be)
        : m_io_service(svc),
          m_config(conf),
          m_backend(be),
          m_stun_server(svc, conf.stun_port()) {
      }

      template<typename Protocol>
      class RegisterFlockServer {
      public:
        RegisterFlockServer(Manager &mgr, std::list< std::shared_ptr<IFlockServer> > &servers)
          : m_manager(mgr), m_servers(servers) {
        }

        void operator()(const typename Protocol::endpoint &ep) {
          m_servers.push_front(std::move(std::make_shared< FlockServer<typename Protocol::acceptor> >(m_manager, ep)));
        }

      private:
        Manager &m_manager;
        std::list< std::shared_ptr<IFlockServer> > &m_servers;
      };

      int Manager::run() {
        for ( const auto &endpoint : config().listen_endpoints() ) {
          BOOST_LOG_TRIVIAL(info) << "Starting on " << endpoint.raw();

          auto ec(uri::run_with_endpoint< RegisterFlockServer, Manager&,
                  std::list< std::shared_ptr<IFlockServer> >& >(service(), endpoint, *this, m_servers));
          switch ( ec.code() ) {
          case uri::success:
            break;
          case uri::missing_port:
            BOOST_LOG_TRIVIAL(error) << "A port number is required for tcp endpoints";
            break;
          case uri::invalid_source:
            BOOST_LOG_TRIVIAL(error) << "System error while resolving " << endpoint.raw()
                                     << ": skipping";
            break;
          case uri::unknown_scheme:
            BOOST_LOG_TRIVIAL(error) << "Unrecognized scheme for url " << endpoint.raw()
                                     << ": skipping";
            break;
          case uri::not_found:
            BOOST_LOG_TRIVIAL(error) << "Could not resolve " << endpoint.host() << ":" << endpoint.port();
            break;
          default:
            BOOST_LOG_TRIVIAL(error) << "Unknown error while resolving " << endpoint.raw() << ": Skipping";
            break;
          }
        }

        unsigned int processors = std::thread::hardware_concurrency();
        std::vector<std::thread> threads;
        for ( ; processors > 1; processors-- )
          threads.push_back(std::thread([this] { service().run(); }));

        service().run();

        return 0;
      }

      //Stun Server

      StunServer::StunServer(boost::asio::io_service &io_svc, std::uint16_t stun_port)
        : m_io_service(io_svc), m_stun_port(stun_port),
          m_tcp_acceptor(io_svc, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v6(), stun_port)),
          m_udp_socket(io_svc, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v6(), stun_port))
      {
        // TODO TCP Acceptor
        //        boost::asio::m_udp_socket.async_receive
      }

    }
  }
}
