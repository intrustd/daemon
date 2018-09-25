#include <boost/bind.hpp>
#include <boost/log/trivial.hpp>
#include <iostream>

#include "../uri_endpoint.hpp"
#include "../queue.hpp"
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
      class FlockSession : public std::enable_shared_from_this< FlockSession<Socket> > {
      public:
        FlockSession(Manager &mgr, Socket s)
          : m_manager(mgr), m_socket(std::move(s)),
            m_frame_sender(m_socket, 4 * 1024),
            m_frame_reader(m_socket, 4 * 1024),
            m_session_state(session_waiting_for_type) {
        }

        virtual ~FlockSession() {
          // TODO schedule unregistering this device
          BOOST_LOG_TRIVIAL(debug) << "Flock session done";
        }

        void start_serve() {
          auto shared(this->shared_from_this());

          m_frame_reader.async_read_frame
            ([this, shared](boost::system::error_code ec) {
                respond_to_request(ec);
            });
        }

      private:
        void parse_type(const std::string &type_str) {
          if ( type_str == "fast" ) {
            m_login_type = login_fast;
            m_session_state = session_waiting_for_appliance;
            start_serve();
          } else if ( type_str == "full" ) {
            m_login_type = login_full;
            m_session_state = session_waiting_for_appliance;
            start_serve();
          } else
            finish_connection_with_error();
        }

        void find_appliance(const std::string &appliance_name) {
          auto shared(this->shared_from_this());

          auto found_device(m_manager.registry().find_device(appliance_name));
          if ( !found_device ) {
            // Signal error
          }

          m_dialing_device = found_device;

          if ( m_login_type == login_fast ) {
            m_session_state = session_waiting_for_persona_id;
            send_success();
          } else {
            m_session_state = session_fetching_appliance_info;
            // Get appliance info
          }
        }

        void receive_ice_candidate(const std::string &candidate) {
          if ( candidate.empty() ) {
            // End of candidates

            if ( m_session_state == session_ice_negotiation_server_done ) {
              // We need to wait until all candidates are transmitted to the server
              m_session_state = session_ice_negotiation_complete;
            } else if ( m_session_state == session_ice_negotiation ) {
              m_session_state = session_ice_negotiation_client_done;
            } else
              finish_connection_with_error();
          } else {
            // Add ICE candidate
          }
        }

        void respond_to_request(boost::system::error_code ec) {
          if ( ec ) {
            BOOST_LOG_TRIVIAL(error) << "Error reading request: " << ec;
          } else {
            const std::string &frame(m_frame_reader.cur_frame());

            switch ( m_session_state ) {
            case session_waiting_for_type:
              parse_type(frame);
              break;
            case session_waiting_for_appliance:
              find_appliance(frame);
              break;
            case session_waiting_for_persona_id:
              m_persona_id = frame;
              m_session_state = session_waiting_for_credentials;
              start_serve();
              break;
            case session_waiting_for_credentials:
              m_credentials = frame;
              m_session_state = session_logging_in;
              // TODO send log in request to server and wait for response
              break;
            case session_waiting_for_connection:
              //              receive_offer(frame);
              break;
            case session_ice_negotiation:
            case session_ice_negotiation_server_done:
              receive_ice_candidate(frame);
              break;
            case session_ice_negotiation_client_done:
            case session_fetching_appliance_info:
            case session_logging_in:
            case session_errored:
            default:
              // We should not be receiving anything here
              finish_connection_with_error();
              break;
            }
          }
        }

        void finish_connection_with_error() {
          boost::unique_lock l(m_cleanup_lock);

          socket_closer<Socket>::close_socket(m_socket);

          if ( m_session_state != session_errored ) {
            BOOST_LOG_TRIVIAL(error) << "Closing connection due to error";

            m_dialing_device.reset();

            m_session_state = session_errored;
          }
        }

        void send_success() {
          static const char *success_rsp = "success";

          m_frame_sender.async_write_raw(boost::asio::buffer(success_rsp, strlen(success_rsp)),
                                         boost::bind(&FlockSession<Socket>::start_serve,
                                                     this->shared_from_this()));
        }

        inline bool is_negotiating_ice() const {
          switch ( m_session_state ) {
          case session_ice_negotiation:
          case session_ice_negotiation_client_done:
          case session_ice_negotiation_server_done:
            return true;
          default:
            return false;
          }
        }

        Manager &m_manager;
        Socket m_socket;

        proto::FramedSender<std::uint16_t, Socket> m_frame_sender;
        proto::FramedReader<std::uint16_t, Socket> m_frame_reader;

        boost::mutex m_cleanup_lock;

        // TODO use atomic
        enum {
          login_invalid = 0,

          // A fast login means we expect the appliance name, persona
          // id, and credential immediately
          login_fast,

          // A full login means persona candidates are gathered and
          // sent to the client before a connection is established
          login_full
        } m_login_type;

        // TODO use atomic
        enum {
          session_waiting_for_type,

          session_waiting_for_appliance,
          session_fetching_appliance_info,
          session_waiting_for_persona_id,
          session_waiting_for_credentials,
          session_logging_in,
          session_waiting_for_connection,
          session_ice_negotiation,
          session_ice_negotiation_client_done,
          session_ice_negotiation_server_done,
          session_ice_negotiation_complete,

          session_errored
        } m_session_state;

        std::shared_ptr<RegisteredDeviceInfo> m_dialing_device;

        std::string m_persona_id, m_credentials;
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

      Manager::Manager(boost::asio::io_service &svc, const Configuration &conf)
        : m_io_service(svc),
          m_config(conf),
          m_registry(m_io_service, m_config),
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

        m_registry.start();

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
