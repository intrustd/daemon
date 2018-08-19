#include <boost/log/utility/manipulators/dump.hpp>
#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int_distribution.hpp>

#include <unordered_set>
#include <thread>
#include <ctime>
#include <sstream>
#include <iostream>
#include <fstream>
#include <streambuf>

#include "uri_endpoint.hpp"
#include "flock/proto.hpp"
#include "random.hpp"
#include "appliance.hpp"
#include "peer/initiator.hpp"
#include "peer/ice.hpp"
#include "container/bridge.hpp"

namespace fs = boost::filesystem;

constexpr int LOGIN_TOKEN_TIMEOUT = 10 * 60;
constexpr int LOGIN_TOKEN_LENGTH = 64;

namespace stork {
  namespace appliance {
    class StorkDirectoryException : public std::exception {
    public:
      StorkDirectoryException(const boost::filesystem::path &stork_path,
                              const char *msg)
        : m_stork_path(stork_path), m_message(msg)
      {
        std::stringstream ss;
        ss << "StorkDirectoryException(" << m_stork_path << "): " << m_message;
        m_formatted = ss.str();
      }
      virtual ~StorkDirectoryException() {
      }

      virtual const char *what() const noexcept {
        return m_formatted.c_str();
      }

    private:
      boost::filesystem::path m_stork_path;
      std::string m_message, m_formatted;
    };

    class IFlockMembership {
    public:
      IFlockMembership(const uri::Uri &flock_uri)
        : m_flock_uri(flock_uri) {
      }
      virtual ~IFlockMembership() {}

      virtual void token_times_out(const std::string &token) =0;
      virtual void answer_dial(const std::string &token, proto::flock::Response::ResponseCode c,
                               const std::string &answer, const std::list<std::string> &ice_candidates) =0;

      inline const uri::Uri &flock_uri() const { return m_flock_uri; }

    private:
      uri::Uri m_flock_uri;
    };

    class FlockPeerInitiator : public peer::PeerInitiator,
                               public container::IUdpListener,
                               public std::enable_shared_from_this<FlockPeerInitiator> {
    public:
      FlockPeerInitiator(boost::asio::io_service &svc, Appliance &appliance,
                         IFlockMembership *flock,
                         const std::string &new_token, const backend::PersonaId &pid)
        : peer::PeerInitiator(svc), m_service(svc), m_appliance(appliance),
          m_persona(pid), m_flock(flock), m_is_ice_done(false), m_is_waiting(false),
          m_udp_packets_in_flight(0) {
        memset(m_token, 'x', sizeof(m_token));
        m_token[LOGIN_TOKEN_LENGTH] = '\0';

        std::copy(new_token.begin(),
                  (new_token.size() <= LOGIN_TOKEN_LENGTH) ?
                   new_token.end() :
                   new_token.begin() + new_token.size(),
                  m_token);

        add_ice_server(uri::Uri("stun://stun.stunprotocol.org"));

      }

      virtual ~FlockPeerInitiator() {
      }

      inline const backend::PersonaId &persona() const { return m_persona; }

      static constexpr int MAX_UDP_PACKETS_IN_FLIGHT = 100;
      virtual void on_udp_packet(const boost::asio::ip::address_v4 &saddr, std::uint16_t sport, std::uint16_t dport,
                                 const boost::asio::const_buffer &b) override {
        BOOST_LOG_TRIVIAL(debug) << "Received UDP packet from internal network on port "
                                 << dport << " from " << saddr << ":" << sport << ": "
                                 << boost::log::dump(boost::asio::buffer_cast<const void *>(b),
                                                     boost::asio::buffer_size(b));

        boost::unique_lock l(m_sctp_mutex);
        if ( saddr != m_sctp_peer->ip() ) return;

        if ( m_udp_packets_in_flight < MAX_UDP_PACKETS_IN_FLIGHT ) {
          m_udp_packets_in_flight++;
          auto data(std::make_shared< std::vector<std::uint8_t> >());
          data->resize(boost::asio::buffer_size(b));
          std::copy(boost::asio::buffer_cast<const std::uint8_t*>(b),
                    boost::asio::buffer_cast<const std::uint8_t*>(b) + data->size(),
                    data->begin());
          m_sctp_in_chan->async_send(boost::asio::buffer(*data),
                                     [data] ( boost::system::error_code ec, std::size_t bytes_tx ) {
                                       if ( ec ) {
                                         BOOST_LOG_TRIVIAL(error) << "Could not send received UDP packet over DTLS: " << ec;
                                       }
                                     });
        }
      }

      virtual void answer_session_description(const std::string &sdp) {
        BOOST_LOG_TRIVIAL(debug) << "Answering SDP: " << sdp;
        m_answer = sdp;
      }

      virtual void send_ice_candidate(const std::string &ice_candidate) {
        m_ice_candidates.push_back(ice_candidate);
      }

      virtual void ice_candidate_collection_complete() {
        boost::unique_lock l(m_completion_mutex);
        m_is_ice_done = true;
        if ( m_is_waiting ) do_answer_dial();
      }

      virtual void on_data_connection_starts(peer::DTLSChannel &chan) {
        BOOST_LOG_TRIVIAL(debug) << "Data connection has started";
        auto shared(shared_from_this());
        boost::unique_lock sctp_l(m_sctp_mutex);
        m_sctp_in_chan = &chan;

        m_appliance.container_mgr().async_launch_persona_container
          (persona(),
           [shared, &chan] (std::error_code ec, std::shared_ptr<container::PersonaContainer> c) {
            if ( ec ) {
              // Shut down conection TODO
              BOOST_LOG_TRIVIAL(error) << "Could not launch persona container: " << ec;
            } else {
              BOOST_LOG_TRIVIAL(info) << "Launched persona container";
              boost::unique_lock sctp_l(shared->m_sctp_mutex);
              shared->m_sctp_peer = c;
              c->async_launch_webrtc_proxy
                ([shared, &chan] (std::error_code ec, container::BridgeController::UsedUdpPort &&p) {
                  if ( ec ) {
                    BOOST_LOG_TRIVIAL(error) << "COuld not launch webrtc proxy: " << ec;
                  } else {
                    // This forwards all UDP traffic on the TUN connection to this tunnel
                    p.listen(shared.get());

                    boost::unique_lock sctp_l(shared->m_sctp_mutex);
                    shared->m_sctp_port = std::make_unique<container::BridgeController::UsedUdpPort>(std::move(p));

                    // Read traffic from this port and output it on our channel
                    //shared->m_appliance.bridge_controller().async_recv_udp(...);

                    // Read traffic from this channel and formulate UDP packets to send on our tun controller
                    shared->read_sctp_in();
                  }
                });
            }
          });

      }

      void wait_for_completion() {
        BOOST_LOG_TRIVIAL(debug) << "Marked complete";
        boost::unique_lock l(m_completion_mutex);

        m_is_waiting = true;
        if ( m_is_ice_done ) do_answer_dial();
      }

      virtual std::shared_ptr<IceCandidateCollector> base_shared_from_this() {
        return shared_from_this();
      }

    protected:
      virtual std::shared_ptr<PeerInitiator> initiator_shared_from_this() {
        return shared_from_this();
      }

    private:
      void do_answer_dial() {
        BOOST_LOG_TRIVIAL(debug) << "Answering dial";
        if ( valid() && connectable() )
          m_flock->answer_dial(m_token, proto::flock::Response::Codes::success,
                               m_answer, m_ice_candidates);
        else
          m_flock->answer_dial(m_token, proto::flock::Response::Codes::invalid_dial,
                               "", m_ice_candidates);
      }

      void read_sctp_in() {
        auto shared(shared_from_this());
        if ( m_sctp_in_chan )
          m_sctp_in_chan->async_receive(boost::asio::buffer(m_sctp_in_buf, sizeof(m_sctp_in_buf)),
                                        boost::bind(&FlockPeerInitiator::on_sctp_packet_read, shared,
                                                    boost::asio::placeholders::error,
                                                    boost::asio::placeholders::bytes_transferred));
      }

      void on_sctp_packet_read(boost::system::error_code ec, std::size_t bytes_rx) {
        if ( ec ) {
          BOOST_LOG_TRIVIAL(error) << "on_sctp_packet_read: " << ec;
        } else {
          boost::shared_lock l(m_sctp_mutex);
          m_sctp_port->write_pkt(m_sctp_peer->ip(), m_sctp_port->port(),
                                 boost::asio::buffer(m_sctp_in_buf, bytes_rx));
          read_sctp_in();
        }
      }

      boost::asio::io_service &m_service;
      Appliance &m_appliance;
      backend::PersonaId m_persona;
      IFlockMembership *m_flock;
      char m_token[LOGIN_TOKEN_LENGTH + 1];

      boost::mutex m_completion_mutex;
      std::string m_answer;
      std::list<std::string> m_ice_candidates;
      bool m_is_ice_done, m_is_waiting;

      boost::shared_mutex m_sctp_mutex;
      std::shared_ptr<container::PersonaContainer> m_sctp_peer;
      std::unique_ptr<container::BridgeController::UsedUdpPort> m_sctp_port;
      peer::DTLSChannel *m_sctp_in_chan;

      char m_sctp_in_buf[1500];
      int m_udp_packets_in_flight;
    };

    Appliance::Appliance(boost::asio::io_service &svc, backend::IBackend &b,
                         nix::NixStore &nix_store,
                         const boost::filesystem::path &stork_path)
      : m_backend(b), m_nix_store(nix_store),
        m_stork_directory(stork_path),
        m_io_service(svc),
        m_app_mgr(m_io_service, *this),
        m_container_mgr(m_io_service, *this),
        m_bridge_controller(m_io_service, m_nix_store, m_container_mgr, m_backend),
        m_flock_management_strand(m_io_service)
    {
      find_stork_init();
      restore_state();
    }

    Appliance::~Appliance() {
    }

    fs::path Appliance::stork_name_path() const {
      fs::path ret(stork_directory());
      ret /= "name";
      return ret;
    }

    fs::path Appliance::stork_local_api_socket_path() const {
      fs::path ret(stork_directory());
      ret /= "api.sock";
      return ret;
    }

    int Appliance::run() {
      unsigned int processors = std::thread::hardware_concurrency();

      BOOST_LOG_TRIVIAL(info) << "Running on " << processors << " processor(s)";

      LocalApi localApi(*this, m_io_service);
      //      FlockClient flockClient(*this, m_io_service);

      //bridger.async_wait_exit([this] () {
      //    m_io_service.stop();
      //  });

      for ( ; processors > 1; processors-- )
        m_threads.push_back(std::thread([this] () { m_io_service.run(); }));

      m_io_service.run();

      return 0;
    }

    std::uintptr_t read_hex(const std::string &s) {
      return std::accumulate(s.begin(), s.end(), 0,
                             [] ( std::uintptr_t a, char next ) {
                               a <<= 4;
                               switch ( next ) {
                               case '0':
                               default:
                                 break;
                               case '1': a |= 0x1; break;
                               case '2': a |= 0x2; break;
                               case '3': a |= 0x3; break;
                               case '4': a |= 0x4; break;
                               case '5': a |= 0x5; break;
                               case '6': a |= 0x6; break;
                               case '7': a |= 0x7; break;
                               case '8': a |= 0x8; break;
                               case '9': a |= 0x9; break;
                               case 'A': case 'a': a |= 0xA; break;
                               case 'B': case 'b': a |= 0xB; break;
                               case 'C': case 'c': a |= 0xC; break;
                               case 'D': case 'd': a |= 0xD; break;
                               case 'E': case 'e': a |= 0xE; break;
                               case 'F': case 'f': a |= 0xF; break;
                               }
                               return a;
                             });
    }

    void Appliance::find_stork_init() {
      m_stork_init_path = "/home/tathougies/Projects/stork-cpp/init/app-instance-init";
//       char *stork_init_env = std::getenv("STORK_INIT");
//       if ( stork_init_env ) {
//         m_stork_init_path = stork_init_env;
//       } else {
//         BOOST_LOG_TRIVIAL(debug) << "Going to find path by examining mappings";
// 
//         // TODO assume that this address is in the executable image
//         std::uintptr_t addr = (std::uintptr_t) (void *) &read_hex;
// 
//         std::fstream maps("/proc/self/maps", std::fstream::in);
//         while ( !maps.eof() ) {
//           std::string start_addr_s, end_addr_s;
//           std::getline(maps, start_addr_s, '-');
//           maps >> end_addr_s;
// 
//           auto start_addr(read_hex(start_addr_s)),
//             end_addr(read_hex(end_addr_s));
// 
//           if ( addr >= start_addr && addr < end_addr ) {
//             std::string data_s;
//             std::getline(maps, data_s);
// 
//             std::stringstream data(data_s);
//             std::string path;
// 
//             while ( !data.eof() )
//               data >> path;
// 
//             m_stork_init_path = path;
//             BOOST_LOG_TRIVIAL(debug) << "Found stork-init: " << m_stork_init_path;
// 
//             break;
//           } else {
//             std::getline(maps, start_addr_s); // Skip to next line
//           }
//         }
//       }
// 
//       if ( m_stork_init_path.empty() )
//         throw std::runtime_error("Unable to locate stork-init. Please specify the STORK_INIT environment variable");
    }

    void Appliance::restore_state() {
      if ( !boost::filesystem::exists(stork_directory()) )
        boost::filesystem::create_directory(stork_directory());

      if ( !boost::filesystem::is_directory(stork_directory()) )
        throw StorkDirectoryException(stork_directory(), "Stork directory exists, but is not directory");

      // restore name
      if ( !boost::filesystem::exists(stork_name_path()) ) {
        generate_new_name(m_appliance_name);
        write_string_to_file(stork_name_path(), m_appliance_name);
      }

      if ( !boost::filesystem::is_regular_file(stork_name_path()) )
        throw StorkDirectoryException(stork_name_path(), "Stork name file does not exist");

      read_string_from_file(stork_name_path(), m_appliance_name);
      BOOST_LOG_TRIVIAL(info) << "Our name is " << m_appliance_name;

      m_backend.async_read_flocks([this] (std::istream &flocks) {
          std::for_each(std::istream_iterator<std::string>(flocks), std::istream_iterator<std::string>(),
                        [this](const std::string &flock_raw) {
                          uri::Uri flock_uri(flock_raw);

                          if ( flock_uri.is_valid() ) {
                            async_join_flock(flock_uri, [this](uri::ErrorCode ec) {
                                if ( !ec )
                                  BOOST_LOG_TRIVIAL(error) << "There was an error joining a flock: " << ec.description();
                              });
                          } else
                            BOOST_LOG_TRIVIAL(info) << "Skipping flock " << flock_raw << " because it is not a valid URI";
                        });
        });
    }

    void Appliance::read_string_from_file(const boost::filesystem::path &path,
                                          std::string &destination) const {
      std::fstream file(path.string().c_str(), std::fstream::in);
      destination.assign(std::istreambuf_iterator<char>(file),
                         std::istreambuf_iterator<char>());
    }

    void Appliance::write_string_to_file(const boost::filesystem::path &path,
                                         const std::string &destination) const {
      std::fstream file(path.string().c_str(), std::fstream::out);
      file << destination;
      file.close();
    }

    void Appliance::generate_new_name(std::string &destination, std::size_t length) const {
      static const char *names[] = {
#include "words.hpp"
      };
      static const int word_cnt = sizeof(names) / sizeof(*names);
      std::vector<const char*> chosen;
      chosen.reserve(4);

      boost::random::mt19937 gen;
      boost::random::uniform_int_distribution<> dist(0, word_cnt - 1);
      gen.seed(std::time(0)); // TODO better random source

      while ( chosen.size() < length ) {
        int next_ix = dist(gen);
        if ( std::find(chosen.begin(), chosen.end(), names[next_ix]) == chosen.end() )
          chosen.push_back(names[next_ix]);
      }

      std::stringstream buf;
      for ( const char *name: chosen ) {
        buf << name << " ";
      }

      destination.assign(buf.str(), 0, buf.str().size() - 1);
    }

    class PeerWithTimeout {
    public:
      PeerWithTimeout(IFlockMembership *owner, const std::string &token,
                      std::shared_ptr<FlockPeerInitiator> peer,
                      boost::posix_time::time_duration timeout)
        : m_owner(owner), m_peer(peer), m_token(token),
          m_timer(peer->service(), timeout),
          m_is_complete(false) {
        m_timer.async_wait(boost::bind(&PeerWithTimeout::timeout, this, boost::placeholders::_1));
      }

      inline std::shared_ptr<FlockPeerInitiator> peer() const { return m_peer; }

      void mark_complete() {
        if ( !m_is_complete.exchange(true) ) {
          m_timer.cancel();
          m_peer->wait_for_completion();
        }
      }

    private:
      void timeout(boost::system::error_code ec) {
        if ( !ec ) {
          if ( !m_is_complete.exchange(true) ) {
            m_owner->token_times_out(m_token);
          }
        }
      }

      IFlockMembership *m_owner;
      std::shared_ptr<FlockPeerInitiator> m_peer;
      std::string m_token;
      boost::asio::deadline_timer m_timer;

      std::atomic_bool m_is_complete;
    };

    template<typename Socket>
    class FlockMembership : public IFlockMembership,
                            public proto::flock::ICommandDispatch {
    public:
      FlockMembership(boost::asio::io_service &svc, const uri::Uri &uri, Appliance &app, const typename Socket::endpoint_type &ep)
        : IFlockMembership(uri),
          m_service(svc),
          m_appliance(app),
          m_endpoint(ep),
          m_socket(svc),
          m_framed_sender(m_socket),
          m_framed_reader(m_socket) {

        start_connect();

      }
      virtual ~FlockMembership() {}

      virtual void token_times_out(const std::string &token) {
        // TODO we need to stop any outstanding requests too probably
        remove_token(token);
      }

      virtual void register_device(const proto::flock::RegisterDeviceCommand &cmd) {
        finish_connection_with_incompatible_command();
      }

      virtual void login_to_device(const proto::flock::LoginToDeviceCommand &cmd) {
        if ( cmd.has_credentials() ) {
          const auto &creds(cmd.credentials());
          BOOST_LOG_TRIVIAL(debug) << "Going to attempt login with " << creds.persona_id().id() << " " << creds.credentials();
          auto persona_id(creds.persona_id());

          // Check if the credentials are valid
          m_appliance.backend().async_check_credentials
            (creds, [this, persona_id] (std::error_code ec) {
              if ( ec ) {
                // TODO Check if error is due to credentials being invalid
                auto r(proto::flock::LoginToDeviceResponse::invalid_credentials());
                write_response(r);
              } else {
                // Otherwise, create a connection token. This token is valid for 10 minutes or so.
                auto new_token(util::random_string(LOGIN_TOKEN_LENGTH));
                auto peer(std::make_shared<FlockPeerInitiator>(m_service, m_appliance, this,
                                                               new_token, persona_id));

                set_token(new_token, peer);

                proto::flock::LoginToDeviceResponse::properties ps;
                ps.push_back(std::make_pair("token", new_token));
                proto::flock::LoginToDeviceResponse r(std::move(ps));
                write_response(r);
              }
            });

        } else {
          auto r(proto::flock::LoginToDeviceResponse::invalid_credentials());
          write_response(r);
        }
      }

      virtual void start_login(const proto::flock::StartLoginCommand &cmd) {
        BOOST_LOG_TRIVIAL(info) << "Request to start login";

        // TODO configure whether we send personas or not
        auto ps(m_appliance.backend().list_personas());
        for ( const auto &p: ps ) {
          proto::flock::LoginToDeviceResponse::properties ps;
          std::string persona_id(p->persona_id().id());

          // TODO configure which properties are sent
          ps.push_back(std::make_pair<std::string, std::string>("id", std::move(persona_id)));
          ps.push_back(std::make_pair<std::string, std::string>("token", util::random_string(32)));

          proto::flock::LoginToDeviceResponse r(std::move(ps));
          m_framed_sender.write(r);
        }

        write_response (proto::flock::LoginToDeviceResponse::no_more_entries());
      }

      virtual void ping(const proto::flock::PingCommand &cmd) {
        write_response(proto::flock::Response(proto::flock::Response::Codes::success));
      }

      virtual void dial_session(const proto::flock::DialSessionCommand &cmd) {
        auto peer_timer(find_peer_conn(cmd.token()));
        if ( peer_timer ) {
          auto peer(peer_timer->peer());
          switch ( cmd.type() ) {
          case proto::flock::DialSessionCommand::session_description:
            if ( peer->valid() )
              peer->set_session_description(cmd.data());
            break;
          case proto::flock::DialSessionCommand::ice_candidate:
            if ( peer->valid() )
              peer->add_ice_candidate(cmd.data());
            break;
          case proto::flock::DialSessionCommand::dial_done: {
            peer_timer->mark_complete(); // Marking it complete sets everything in motion to wait for the dial to complete
            auto initiator(remove_token(cmd.token())); // Must come after because peer_timer otherwise is wrong

            //            initiator->start_peer();

            return;
          }
          default:
            BOOST_LOG_TRIVIAL(error) << "Malformed dial session command";

            // This seems harsh, but the flock server is expected to
            // filter out inappropriate dial commands
            finish_connection_with_error();
            return;
          }
        }

        m_service.post([this] () { serve_flock_requests(); });
      }

      virtual void answer_dial(const std::string &token, proto::flock::Response::ResponseCode c,
                               const std::string &sdp, const std::list<std::string> &candidates) {
        if ( c == proto::flock::Response::Codes::success ) {
          write_response(proto::flock::DialResponse(sdp, candidates));
        } else
          write_response(proto::flock::Response(c));
      }

    private:
      void set_token(const std::string &token, std::shared_ptr<FlockPeerInitiator> peer) {
        boost::unique_lock token_lock(m_tokens_mutex);
        m_tokens[token] = std::make_unique<PeerWithTimeout>(this, token, peer, boost::posix_time::seconds(LOGIN_TOKEN_TIMEOUT));
      }

      std::shared_ptr<FlockPeerInitiator> remove_token(const std::string &token) {
        boost::unique_lock token_lock(m_tokens_mutex);
        auto found(m_tokens.find(token));
        if ( found == m_tokens.end() )
          return nullptr;
        else {
          auto r(found->second->peer());
          m_tokens.erase(found);
          return r;
        }
      }

      PeerWithTimeout *find_peer_conn(const std::string &token) {
        boost::unique_lock token_lock(m_tokens_mutex);
        auto token_p(m_tokens.find(token));
        if ( token_p == m_tokens.end() )
          return nullptr;
        else
          return token_p->second.get();
      }

      void write_response(const proto::flock::Response &r) {
        m_framed_sender.write(r);
        m_service.post([this] () { serve_flock_requests(); });
      }

      void start_connect() {
        // TODO use exponential back off with jitter on failure
        m_socket.async_connect
          (m_endpoint,
           [this] (boost::system::error_code ec) {
            if ( ec ) {
              BOOST_LOG_TRIVIAL(error) << "Could not join flock " << flock_uri().raw() << ": " << ec;
            } else
              start_registration();
          });
      }

      void start_registration() {
        proto::flock::RegisterDeviceCommand registration_command(1, m_appliance.appliance_name());

        m_framed_sender.async_write(registration_command,
                                    [this](boost::system::error_code ec) {
                                      if ( ec ) {
                                        BOOST_LOG_TRIVIAL(error) << "Could not send registration command: " << ec;
                                      } else {
                                        m_framed_reader.async_read_frame([this](boost::system::error_code ec) {
                                            handle_registration_response(ec);
                                          });
                                      }
                                    });
      }

      void handle_registration_response(boost::system::error_code ec) {
        if ( ec ) {
          BOOST_LOG_TRIVIAL(error) << "Error while receiving registration response: " << ec;

          // TODO re-attempt connection using exponential back off
        } else {
          try {
            proto::flock::RegisterDeviceResponse resp(m_framed_reader.template read<proto::flock::RegisterDeviceResponse> ());

            if ( resp.proto_version() > 1 )
              BOOST_LOG_TRIVIAL(warning) << "Flock server is using a newer protocol";

            if ( resp.status() == proto::flock::Response::Codes::success ) {
              BOOST_LOG_TRIVIAL(info) << "Joined flock " << m_endpoint;

              serve_flock_requests();
            } else {
              BOOST_LOG_TRIVIAL(error) << "Could not join flock: " << resp.status_string();
            }
          } catch ( proto::ProtoParseException &e) {
            BOOST_LOG_TRIVIAL(error) << "Could not parse RegisterDeviceResponse";
          }
        }
      }

      void serve_flock_requests() {
        BOOST_LOG_TRIVIAL(info) << "Serving flock requests";
        m_framed_reader.async_read_frame([this](boost::system::error_code ec) {
            BOOST_LOG_TRIVIAL(info) << "Read flock frame";
            if ( ec ) {
              BOOST_LOG_TRIVIAL(error) << "Error while attempting to serve flock request: " << ec;
              finish_connection_with_error_code(ec);
            } else {
              const std::string &frame(m_framed_reader.cur_frame());
              std::stringstream frame_stream(frame);
              proto::ProtoParser frame_parser(frame_stream);

              try {
                auto command = proto::flock::Command::read(frame_parser);

                if ( command ) {
                  command->dispatch(*this);
                } else {
                  BOOST_LOG_TRIVIAL(error) << "Invalid request";
                  finish_connection_with_error();
                }
              } catch (proto::ProtoParseException &e) {
                BOOST_LOG_TRIVIAL(error) << "Failed to parse request: " << e.what();
                finish_connection_with_error();
              }
            }
          });
      }

      void finish_connection_with_error_code(boost::system::error_code ec) {
        finish_connection_with_error();
      }

      void finish_connection_with_incompatible_command() {
        finish_connection_with_error();
      }

      void finish_connection_with_error() {
        BOOST_LOG_TRIVIAL(debug) << "TODO: FlockMembership::finish_connection_with_error: should signal appliance class";
      }

      boost::asio::io_service &m_service;
      Appliance &m_appliance;
      typename Socket::endpoint_type m_endpoint;
      Socket m_socket;

      proto::FramedSender<std::uint16_t, Socket> m_framed_sender;
      proto::FramedReader<std::uint16_t, Socket> m_framed_reader;

      boost::mutex m_tokens_mutex;
      std::unordered_map<std::string, std::unique_ptr<PeerWithTimeout> > m_tokens;
    };

    template<typename Protocol>
    class RegisterFlockMembership {
    public:
      RegisterFlockMembership(boost::asio::io_service &svc, const uri::Uri &uri, Appliance &app, std::list< std::shared_ptr<IFlockMembership> > &flocks)
        : m_service(svc), m_uri(uri), m_appliance(app), m_flocks(flocks) {
      }

      ~RegisterFlockMembership() {
        // TODO we should fall back on other endpoints if one doesn't work out
        if ( m_endpoints.size() > 0 )
          m_flocks.push_front(std::make_shared< FlockMembership<typename Protocol::socket> >(m_service, m_uri, m_appliance, *m_endpoints.begin()));
      }

      void operator() (const typename Protocol::endpoint &ep) {
        m_endpoints.push_front(ep);
      }

    private:
      boost::asio::io_service &m_service;
      const uri::Uri &m_uri;
      Appliance &m_appliance;
      std::list< std::shared_ptr<IFlockMembership> > &m_flocks;
      std::list< typename Protocol::endpoint > m_endpoints;
    };

    const boost::filesystem::path &Appliance::persona_init_path() const {
      static const boost::filesystem::path ret("/home/tathougies/Projects/stork-cpp/init/persona-init");
      return ret;
    }

    void Appliance::async_join_flock(uri::Uri flock_uri,
                                     std::function<void(uri::ErrorCode)> cb) {
      m_flock_management_strand.dispatch
        ([this, flock_uri{std::move(flock_uri)}, cb] () {
          auto found(std::find_if(m_flocks.begin(), m_flocks.end(),
                                  [&flock_uri](std::shared_ptr<IFlockMembership> fm) {
                                    return fm->flock_uri() == flock_uri;
                                  }));

          if ( found != m_flocks.end() )
            m_io_service.post(boost::bind(cb, uri::ErrorCode()));
          else {
            auto ec(uri::run_with_endpoint< RegisterFlockMembership, boost::asio::io_service&, const uri::Uri&, Appliance&,
                    std::list< std::shared_ptr<IFlockMembership> >& >(m_io_service, flock_uri,
                                                                      m_io_service, flock_uri, *this, m_flocks));

            m_io_service.post(boost::bind(cb, ec));
          }
        });
    }

    void Appliance::async_save_flocks() {
      std::unordered_set<std::string> flocks;

      for ( auto &membership : m_flocks ) {
        flocks.insert(membership->flock_uri().canonical());
      }

      m_io_service.post([this, flocks{std::move(flocks)}] () {
          BOOST_LOG_TRIVIAL(debug) << "Writing flock data";
          std::stringstream flock_data;
          for ( const auto &flock : flocks ) {
            flock_data << flock << std::endl;
          }
          m_backend.save_flocks(flock_data.str());
        });
    }
  }
}
