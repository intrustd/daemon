#include <boost/log/utility/manipulators/dump.hpp>
#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>

#include "packet.hpp"

namespace stork {
  namespace sctp {
    SctpChunkProcessor::SctpChunkProcessor(SctpManagerBase &mgr, SctpPacketBuilder &response,
                                           const boost::asio::ip::address &source,
                                           SctpHeaderPtr hdr)
      : m_manager(mgr), m_source(source), m_packet(hdr), m_has_seen_init(false),
        m_has_seen_packets(false), m_has_errored(false), m_has_response(false),
        m_response(response) {

      m_destination_port = m_manager.get_port(m_packet->destination_port(), false);

    }

    void SctpChunkProcessor::init_chunk(InitChunk &chunk) {
      on_chunk();

      if ( is_processing_packets() ) {
        m_has_seen_init = true;

        if ( !m_destination_port ) {
          m_destination_port = m_manager.get_port(m_packet->destination_port());
        }

        if ( m_destination_port && m_destination_port->is_listening() ) {
          boost::random_device rd;
          boost::random::uniform_int_distribution<std::uint32_t> tag_gen;

          m_response.header().verification_tag(chunk.initiate_tag());

          std::uint32_t our_tag(tag_gen(rd));
          // Generate verification tag and cookie
          std::uint16_t ib_streams(std::min<std::uint16_t>(chunk.num_outbound(), 1024)),
            ob_streams(std::min<std::uint16_t>(chunk.num_inbound(), 1024));
          std::uint32_t initial_tsn(our_tag); // TODO generate random

          m_has_response = true;

          std::uint32_t default_rwnd(0x20000);
          InitAckChunk our_ack(our_tag, default_rwnd, ob_streams, ib_streams, initial_tsn);
          m_response.write_chunk(our_ack); // TODO a_rwnd

          time_t mac_time;
          std::uint8_t mac_key[SctpManagerBase::MAC_KEY_SIZE];
          m_manager.current_mac_key(mac_key, mac_time);
          m_response.write_parameter(StateCookie(chunk, our_ack,
                                                 mac_time, mac_key,
                                                 SctpManagerBase::MAC_KEY_SIZE));

          for ( auto &param : chunk ) {
            BOOST_LOG_TRIVIAL(debug) << "Received init of type " << (std::uint16_t) param.type();

            bool stop_processing(false);

            switch ( param.type() ) {
            default:
              if ( param.if_unrecognized().send_report() ) {
                m_response.emplace_parameter<UnrecognizedParameter>(param);
              }

              if ( param.if_unrecognized().stop_processing() ) {
                BOOST_LOG_TRIVIAL(debug) << "Will stop processing this parameter";
                stop_processing = true;
                break;
              }
            }

            if ( stop_processing ) break;
          }

        } else if ( !m_destination_port ) {
          out_of_resources();
        } else {
          refuse_association();
        }
      }
    }

    void SctpChunkProcessor::cookie_echo(CookieEcho &echo) {
      if ( m_has_seen_packets ) {
        m_has_errored = true;
      } else {
        on_chunk();

        if ( is_processing_packets() ) {
          if ( echo.header().padded_size() < sizeof(StateCookieData) ) {
            BOOST_LOG_TRIVIAL(error) << "Cookie is too small";
            m_has_errored = true;
          } else {
            BOOST_LOG_TRIVIAL(info) << "Received cookie echo with data "
                                    << boost::log::dump(echo.data(), echo.header().raw_size());

            auto &cookie(echo.cookie());
            if ( !verify_tag(cookie.local_verification_tag()) ) {
              return;
            }

            std::uint8_t mac_key[SctpManagerBase::MAC_KEY_SIZE];

            if ( m_manager.mac_key_at_time(mac_key, cookie.timestamp()) &&
                 cookie.verify_mac(mac_key, sizeof(mac_key)) ) {
              BOOST_LOG_TRIVIAL(info) << "Verified cookie. Going to create association";
              //              auto assoc(m_manager.new_association(*m_packet, echo.cookie()));
              if ( !m_destination_port ) {
                invalid_association();
                return;
              }

              auto assoc_res(m_destination_port->receive_association(m_source, *m_packet, cookie));

              switch ( assoc_res ) {
              case SctpOpenPort::association_rejected:
                refuse_association();
                break;
              case SctpOpenPort::association_error_no_mem:
                BOOST_LOG_TRIVIAL(debug) << "Association rejected because we're out of resources";
                out_of_resources();
                break;
              case SctpOpenPort::association_already_exists:
              case SctpOpenPort::association_created:
                m_has_response = true;
                m_response.header().verification_tag(cookie.remote_verification_tag());
                m_response.write_chunk(CookieAckChunk());
                break;
              }
            } else {
              BOOST_LOG_TRIVIAL(error) << "Could not verify state cookie";
              m_has_errored = true;
            }
          }
        }
      }
    }

    void SctpChunkProcessor::data_chunk(DataChunk &chunk) {
      on_chunk();

      if ( is_processing_packets() ) {
        if ( !m_destination_port ) {
          BOOST_LOG_TRIVIAL(debug) << "Message sent to unopened port is being ignored";
          // TODO send abort with cause code
          return;
        }

        auto assoc(m_destination_port->find_association(m_source));
        if ( !assoc ) {
          BOOST_LOG_TRIVIAL(debug) << "No association with " << m_source;
          // TODO send abort with cause code
          return;
        }

        if ( !verify_tag(assoc->local_verification_tag()) ) return;

        m_response.header().verification_tag(assoc->remote_verification_tag());
        m_association = assoc;

        BOOST_LOG_TRIVIAL(debug) << "This data chunk has been validated... it will now be delivered";

        m_association->deliver_chunk(chunk);
      }
    }

    void SctpChunkProcessor::unknown_chunk_type(SctpChunkHeader &chunk) {
      on_chunk();

      BOOST_LOG_TRIVIAL(debug) << "UNKNOWN SCTP CHUNK TYPE " << chunk.chunk_type();
    }

    void SctpChunkProcessor::out_of_resources() {
      // TODO
    }

    void SctpChunkProcessor::refuse_association() {
      // TODO
      BOOST_LOG_TRIVIAL(error) << "Refusing association, for some reason";
    }

    void SctpChunkProcessor::unverified_tag() {
      // TODO
      BOOST_LOG_TRIVIAL(error) << "Rejecting chunk because of verification tag";
    }

    void SctpChunkProcessor::invalid_association() {
      // TODO
      BOOST_LOG_TRIVIAL(error) << "Rejecting chunk because it was sent to an unopened port";
    }

    bool SctpChunkProcessor::verify_tag(std::uint32_t expected) {
      BOOST_LOG_TRIVIAL(debug) << "verify_tag(" << expected << "): tag is " << m_packet->verification_tag();
      if ( m_packet->verification_tag() == expected )
        return true;
      else {
        unverified_tag();
        return false;
      }
    }

    bool SctpChunkProcessor::process() {

      if ( m_response.overflow() ) {
        // TODO Error out
        BOOST_LOG_TRIVIAL(error) << "Cannot respond, because the response buffer overflowed";
        return false;
      } else if ( m_has_errored ) {
        return false;
      } else {
        if ( m_association )
          m_association->send_sack_if_necessary(m_response);

        if ( m_response.has_chunks() ) {
          BOOST_LOG_TRIVIAL(debug) << "SctpChunkProcessor: will respond: " << (m_has_response ? " has response, " : "" ) << (m_has_errored ? "has error" : "");

          m_response.finish();
          return true;
        } else
          return false;
      }
    }

    void SctpChunkProcessor::on_chunk() {
      m_has_seen_packets = true;
      if ( m_has_seen_init ) {
        // TODO This is an error
        m_has_errored = true;
      }
    }
  }
}
