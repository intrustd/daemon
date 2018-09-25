#include <boost/bind.hpp>
#include <boost/log/trivial.hpp>
#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>

#include "registry.hpp"
#include "appliance_proto.hpp"

namespace stork {
  namespace flock {
    namespace flockd {
      RegisteredDeviceInfo::RegisteredDeviceInfo(ApplianceRegistry &reg,
                                                 const std::string &name,
                                                 const crypto::Key &kp)
        : m_name(name), m_registry(reg), m_appliance_key(kp),
          m_persona_cache_expiry_timer(reg.service()),
          m_device_timer(reg.service()),
          m_cached_personas(false) {
        touch();
      }

      RegisteredDeviceInfo::~RegisteredDeviceInfo() {
        m_persona_cache_expiry_timer.cancel();
        m_device_timer.cancel();

        boost::unique_lock l(m_device_lock);
        // Also, signal error on all connections active
        for ( auto client : m_connections ) {
          m_device_timer.get_io_service().post(boost::bind(&IIceSignaller::on_ice_error, client.second));
        }
      }

      std::shared_ptr<IIceSignaller> RegisteredDeviceInfo::get_connection(std::uint32_t ctag) {
        boost::unique_lock l(m_device_lock);
        auto found(m_connections.find(ctag));
        if ( found == m_connections.end() ) return nullptr;
        else return found->second;
      }

      void RegisteredDeviceInfo::update_persona_cache(std::string &&persona_info,
                                                      boost::posix_time::time_duration m_keep_alive) {
        boost::unique_lock l(m_device_lock);

        m_cached_personas = true;
        m_cached_persona_info = std::move(persona_info);

        m_persona_cache_expiry_timer.expires_from_now(m_keep_alive);
        m_persona_cache_expiry_timer.async_wait
          (boost::bind(&RegisteredDeviceInfo::expiry_timer_expires,
                       this, boost::placeholders::_1));
      }

      void RegisteredDeviceInfo::expiry_timer_expires(boost::system::error_code ec) {
        if ( !ec ) {
          boost::unique_lock l(m_device_lock);
          m_cached_personas = false;
          m_cached_persona_info.clear();
        }
      }

      void RegisteredDeviceInfo::device_timer_expires(boost::system::error_code ec) {
        if ( !ec )
          m_registry.unregister_appliance(m_name);
      }

      void RegisteredDeviceInfo::touch() {
        m_device_timer.cancel();
        m_device_timer.expires_from_now(boost::posix_time::seconds(60));
        m_device_timer.async_wait(boost::bind(&RegisteredDeviceInfo::device_timer_expires,
                                              this, boost::placeholders::_1));
      }

      // ApplianceRegistry
      ApplianceRegistry::ApplianceRegistry(boost::asio::io_service &svc,
                                           const Configuration &conf)
        : m_service(svc), m_conf(conf), m_socket(svc), m_inflight(0) {

      }

      void ApplianceRegistry::start() {
        m_shards.reserve(m_conf.shards().size());

        BOOST_LOG_TRIVIAL(info) << "Resolving shards";
        boost::system::error_code ec;
        boost::asio::ip::udp::resolver resolver(m_socket.get_io_service());
        boost::random::random_device rdev;
        for ( const auto &shard: m_conf.shards() ) {
          // Lookup the shard and add it to the back of the shard list
          auto results(resolver.resolve(shard.host(), shard.port_text(), ec));
          if ( !ec ) {
            boost::random::uniform_int_distribution<int> dist(0, results.size() - 1);
            std::advance(results, dist(rdev));

            m_shards.push_back(*results);
          } else {
            BOOST_LOG_TRIVIAL(error) << "Could not resolve " << shard.raw() << ": " << ec;
          }
        }

        BOOST_LOG_TRIVIAL(info) << "Resolving appliance endpoint";
        // Open the socket and start serving
        auto results(resolver.resolve(m_conf.appliance_endpoint().host(),
                                      m_conf.appliance_endpoint().port_text(), ec));
        if ( ec ) {
          BOOST_LOG_TRIVIAL(error) << "Could not resolve appliance endpoint "
                                   << m_conf.appliance_endpoint().raw() << ": " << ec;
        } else if ( results.size() == 0 ) {
          BOOST_LOG_TRIVIAL(error) << "Could not resolve appliance endpoint";
        } else {
          m_socket.open(results->endpoint().protocol(), ec);
          if ( ec )
            BOOST_LOG_TRIVIAL(error) << "Could not open socket: " << ec;

          m_socket.bind(results->endpoint(), ec);
          if ( ec )
            BOOST_LOG_TRIVIAL(error) << "Could not bind socket: " << ec;

          BOOST_LOG_TRIVIAL(info) << "Listening on " << results->endpoint();

          start_serve();
        }
      }

      void ApplianceRegistry::start_serve() {
        boost::unique_lock l(m_inflight_mutex);
        start_serve_after_lock();
      }

      void ApplianceRegistry::start_serve_after_lock() {
        if ( m_inflight < MAX_INFLIGHT ) {
          m_inflight++;

          auto packet(alloc_packet());
          m_socket.async_receive_from(boost::asio::buffer(*packet), m_packet_endpoint,
                                      [this, packet] ( boost::system::error_code ec, std::size_t num ) {
                                        if ( ec ) {
                                          BOOST_LOG_TRIVIAL(error) << "Could not read from socket: " << ec;
                                        } else {
                                          packet->resize(num);
                                          process_packet(m_packet_endpoint, *packet);
                                          serve_next(packet);
                                        }
                                      });
        }
      }

      void ApplianceRegistry::serve_next(std::shared_ptr< std::vector<std::uint8_t> > b) {
        boost::unique_lock l(m_inflight_mutex);

        m_inflight--;
        b->resize(DEF_PKT_SZ);
        m_released_inflight.push_back(b);
      }

      std::shared_ptr< std::vector<std::uint8_t> > ApplianceRegistry::alloc_packet() {
        if ( m_released_inflight.empty() ) {
          return std::make_shared< std::vector<std::uint8_t> >(DEF_PKT_SZ);
        } else {
          auto ret(m_released_inflight.back());
          m_released_inflight.pop_back();
          return ret;
        }
      }

      void ApplianceRegistry::decrypt_packet(const std::vector<std::uint8_t> &in_data,
                                             std::uint8_t *out_data, std::size_t &out_sz,
                                             std::error_code &ec) {
        ec = std::error_code();

        if ( m_packet_decrypter.get() ) {
          m_packet_decrypter.reset(new crypto::KeyContext(m_conf.private_key()));
        }

        m_packet_decrypter->decrypt(in_data.data(), in_data.size(),
                                    out_data, out_sz,
                                    ec);
      }

      void ApplianceRegistry::process_packet(boost::asio::ip::udp::endpoint ep,
                                             std::vector<std::uint8_t> &pkt) {
        BOOST_LOG_TRIVIAL(info) << "Process packet";

        // Steps:
        //   1. Decode the packet
        //
        //   2. If the magic doesn't line up, send a copy of the
        //   public key back
        //
        //   3. If the magic is okay, then check that the signature
        //   works. If it doesn't send no response
        //
        //   4. Check connection tag. If the tag is 0, then the
        //   payload is the appliance public key. If the appliance
        //   does not exist, then store the appliance, and the hash of
        //   the public key. If the appliance exists, reset the timer
        //   if the request matches. Otherwise do nothing, and send
        //   error.
        //
        //   5. If the tag is not zero, then check if the appliance
        //   with the given name exists. If it does, then check the
        //   connection tag validity. If it is invalid, send an
        //   error. if the appliance does not exist, send an error.
        //
        //   6. If the connection tag is valid, then send the ice
        //   candidate on the channel.

        std::uint8_t pkt_out[DEF_PKT_SZ];
        std::size_t pkt_out_sz(DEF_PKT_SZ);
        std::error_code ec;

        decrypt_packet(pkt, pkt_out, pkt_out_sz, ec);
        if ( ec ) {
          BOOST_LOG_TRIVIAL(debug) << "Ignoring packet from " << ep << " could not decrypt";
          return;
        }

        ApplianceMessage *req((ApplianceMessage *)pkt_out);

        if ( !req->verify_size(pkt_out_sz) ) {
          BOOST_LOG_TRIVIAL(debug) << "Ignoring packet of improper size";
          return;
        }

        if ( req->magic() == ApplianceMessage::APPLIANCE_MAGIC ) {
          std::string appliance_name(req->appliance_name());
          boost::unique_lock l(m_appliances_mutex);
          auto found(m_appliances.find(appliance_name));

          // Check the connection tag
          if ( req->is_registration() ) {
            if ( found != m_appliances.end() ) {
              // Check that the provided public key is the same as the
              // recorded one and the endpoints match

              BOOST_LOG_TRIVIAL(debug) << "TODO check that the keys match";
            }

            // Check that the message integrity validates itself with
            // the given public key

            if ( found == m_appliances.end() ) {
              crypto::Key kp;
              kp.from_asn1_encoded_public_key(req->raw_payload(), req->payload_size());
              if ( !kp.valid() ) {
                BOOST_LOG_TRIVIAL(error) << "Could not read public key from payload";
              } else {
                m_appliances.insert(std::make_pair(appliance_name,
                                                   std::make_shared<RegisteredDeviceInfo>(*this, appliance_name, kp)));
              }
            } else {
              found->second->touch();
            }
          } else {
            // Attempt to find the appliance and verify the message
            // integrity
            if ( found == m_appliances.end() ) {
              // Send back error
              send_response(ApplianceMessage::no_such_appliance(req->connection_tag(), req->payload_tag()));
            } else {
              // Attempt to verify message
              if ( req->verify_message(found->second->public_key()) ) {
                auto connPtr(found->second->get_connection(req->connection_tag()));
                if ( !connPtr ) {
                  BOOST_LOG_TRIVIAL(debug) << "No such connection for " << appliance_name << ": " << req->connection_tag();
                  send_response(ApplianceMessage::no_such_connection(req->connection_tag(), req->payload_tag()));
                } else {
                  // We have the connection
                  if ( req->is_end_of_candidates() )
                    m_service.post(boost::bind(&IIceSignaller::on_ice_candidates_done, connPtr));
                  else
                    m_service.post(boost::bind(&IIceSignaller::on_ice_candidate, connPtr, req->ice_candidate()));
                  send_response(ApplianceMessage::confirm_candidate(req->connection_tag(), req->payload_tag()));
                }
              } else
                BOOST_LOG_TRIVIAL(debug) << "Ignoring message from " << ep << " because it was corrupted";
            }
          }
        } else {
          BOOST_LOG_TRIVIAL(debug) << "Sending back public key";
        }
      }

      std::shared_ptr<RegisteredDeviceInfo> ApplianceRegistry::find_device(const std::string &name) {
        boost::unique_lock l(m_appliances_mutex);
        auto i(m_appliances.find(name));
        if ( i == m_appliances.end() ) return nullptr;
        else return i->second;
      }

      void ApplianceRegistry::unregister_appliance(const std::string &name) {
        boost::unique_lock l(m_appliances_mutex);
        auto i(m_appliances.find(name));
        if ( i == m_appliances.end() ) return;
        m_appliances.erase(i);
      }
    }
  }
}
