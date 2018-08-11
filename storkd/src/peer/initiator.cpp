#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>

#include "../random.hpp"
#include "../util/heap.hpp"
#include "initiator.hpp"
#include "parse_utils.hpp"

namespace stork {
  namespace peer {
    static const char *ice_chars =
      "abcdefghijklmnopqrstuvwxyz"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "0123456789+/";

    template<typename CandidatePtr>
    class HigherPriority {
    public:
      bool operator() (CandidatePtr a, CandidatePtr b) {
        return ice_candidate(*a).priority() > ice_candidate(*b).priority();
      }
    };

    PeerInitiator::PeerInitiator(boost::asio::io_service &svc)
      : IceCandidateCollector(svc), DTLSContext(true),
        m_service(svc), m_tie_breaker(0),
        m_received_sdp(false), m_received_sdp_valid(false),
        m_session_description(*this), m_session_answer(*this),
        m_check_timer(svc), m_check_ta(boost::posix_time::milliseconds(400)),
        m_checks_running(false) {
      m_local_cert.generate();

      m_tie_breaker = boost::random::uniform_int_distribution<std::uint64_t>()(gen());

      complete_setup();
    }

    PeerInitiator::~PeerInitiator() {
    }

    boost::asio::io_service &PeerInitiator::service() const {
      return m_service;
    }

    void PeerInitiator::set_session_description(const std::string &sdp) {
      if ( !m_received_sdp ) {
        BOOST_LOG_TRIVIAL(debug) << "Received session description: " << sdp;
        m_received_sdp = true;
        SessionParser parser(m_session_description);

        parser.parse_more(sdp);
        parser.finish();

        if ( parser.valid() && m_session_description.data_stream() ) {
          m_received_sdp_valid = true;
          // If this is valid, then start ICE initiation
          async_collect_candidates();

          // Create SDP answer
          create_answer();
        } else {
          BOOST_LOG_TRIVIAL(error) << "Invalid session description: " << parser.error_string()
                                   << " at " << parser.current_line() << ":" << parser.current_column();
        }
      } else {
        BOOST_LOG_TRIVIAL(error) << "Received multiple session descriptions. Marking invalid";
      }
    }

    void PeerInitiator::add_ice_candidate(const std::string &candidate) {
      BOOST_LOG_TRIVIAL(debug) << "Received remote ice candidate: " << candidate;
      IceCandidate ice;
      if ( ice.from_string(candidate) ) {
        BOOST_LOG_TRIVIAL(debug) << "Parsed remote ice candidate: " << ice.as_sdp_string();
        boost::unique_lock l(m_candidate_mutex);
        if ( m_remote_candidates.has_space() )
          m_remote_candidates.push_back(ice);

        for ( auto local(m_local_candidates.begin()); local != m_local_candidates.end(); ++local )
          m_checklist.add_candidate_pair(m_remote_candidates.end() - 1, local);
        start_checks();
      }
    }

    void PeerInitiator::on_receive_ice_candidate(const IceCandidate &c) {
      boost::unique_lock l(m_candidate_mutex);

          // Only push if there's enough space in the list, or this candidate priority is greater than the smallest priority in the list
      if ( m_local_candidates.has_space() ||
           (c.priority() > m_local_candidates_heap.front()->candidate().priority()) ) {

        auto new_ice(c);
        new_ice.foundation(util::random_string(32).c_str());

        // We only have one component (data)
        new_ice.component_id(1);
        new_ice.priority(new_ice.recommended_priority(0));

        auto local_candidate(new_ice.base());

        auto found(std::find_if(m_local_candidates_heap.begin(), m_local_candidates_heap.end(),
                                [ &local_candidate ] ( const LocalIceCandidates::iterator &c ) {
                                  return c->candidate().is_redundant(local_candidate);
                                }));
        LocalIceCandidates::iterator inserted_candidate(NULL);

        // This candidate is new
        if ( found == m_local_candidates_heap.end() ) {
          // This candidate is not redundant

          if ( !m_local_candidates.has_space() ) {
            std::pop_heap(m_local_candidates_heap.begin(), m_local_candidates_heap.end(), HigherPriority<LocalIceCandidates::iterator>());

            // TODO remove candidate pairs

            m_local_candidates_heap.resize(LocalIceCandidates::max_size - 1);
          }

          auto connectivity_checker(start_connectivity(l, local_candidate));
          m_local_candidates.push_back(LocalIceCandidate(connectivity_checker, local_candidate));
          inserted_candidate = m_local_candidates.end() - 1;
          connectivity_checker->async_start();

          // Turn this into a min heap
          std::push_heap(m_local_candidates_heap.begin(), m_local_candidates_heap.end(), HigherPriority<LocalIceCandidates::iterator>());

        } else if ( (*found)->candidate().priority() < local_candidate.priority() ) {
          (*found)->replace_candidate(local_candidate);
          inserted_candidate = *found;
          util::decrease_heap_key(m_local_candidates_heap.begin(), found, HigherPriority<LocalIceCandidates::iterator>());
        }

        assert(inserted_candidate);

        BOOST_LOG_TRIVIAL(debug) << "Received local ice candidate " << new_ice.as_sdp_string();
        send_ice_candidate(new_ice.as_sdp_string());

        // Now try to form candidate pairs
        for ( auto remote(m_remote_candidates.begin());
              remote != m_remote_candidates.end();
              ++remote )
          m_checklist.add_candidate_pair(remote, inserted_candidate);
        start_checks();
      }
    }

    std::shared_ptr<IceConnectivityListener> PeerInitiator::start_connectivity(const boost::unique_lock<boost::upgrade_mutex> &l,
                                                                               const IceCandidate &c) {
      boost::asio::ip::udp::endpoint local_ep(c.addr(), c.port());
      std::shared_ptr<IceConnectivityListener> r;
      m_listeners.remove_if
        ([&r, &local_ep] ( std::weak_ptr<IceConnectivityListener> l ) {
          auto retrieved(l.lock());
          if ( retrieved ) {
            if ( retrieved->local_endpoint() == local_ep )
              r = retrieved;
            return false;
          } else
            return true;
        });

      if ( r )
        return r;
      else {
        assert(m_listeners.has_space() && m_session_description.data_stream() && m_session_answer.data_stream());
        r = std::make_shared<IceConnectivityListener>(m_service, local_ep,
                                                      *m_session_description.data_stream(),
                                                      *m_session_answer.data_stream(),
                                                      initiator_shared_from_this());
        m_listeners.push_back(r);
        return r;
      }
    }

    void PeerInitiator::start_checks() {
      if ( !m_checks_running ) {
        m_checks_running = true;

        m_service.post(boost::bind(&PeerInitiator::run_scheduled_check, initiator_shared_from_this(), boost::system::error_code()));
      }
    }

    void PeerInitiator::run_scheduled_check(boost::system::error_code ec) {
      if ( !ec ) {
        BOOST_LOG_TRIVIAL(debug) << "Attempting to run a check";
        // Send a check
        boost::upgrade_lock read_lock(m_candidate_mutex);

        if ( m_checklist.has_waiting() ) { // TODO check for triggered checks
          boost::upgrade_to_unique_lock write_lock(read_lock);
          BOOST_LOG_TRIVIAL(debug) << "Found a waiting candidate";
          // Check if we have candidates for which we need to send out checks
          auto &pair_to_check(m_checklist.pop_waiting());
          assert(pair_to_check.is_frozen_or_waiting());

          pair_to_check.start_check(StunTransactionId(gen()));

          auto shared(initiator_shared_from_this());
          pair_to_check.local()->listener().send_connectivity_check
            (pair_to_check, [ shared, &pair_to_check ] ( boost::system::error_code ec ) {
              shared->conn_check_completes(pair_to_check, ec);
            });
        } else if ( !m_checklist.has_failed() ) {
          BOOST_LOG_TRIVIAL(debug) << "No more candidates left to check...";
          boost::upgrade_to_unique_lock write_lock(read_lock);
          m_checks_running = false;
        }
      }
    }

    void PeerInitiator::conn_check_completes(CandidatePair &pair, boost::system::error_code ec) {
      if ( ec ) {
        boost::unique_lock read_lock(m_candidate_mutex);
        // Signal an error
        BOOST_LOG_TRIVIAL(error) << "Connectivity check sending failed";
      }

      m_check_timer.expires_from_now(m_check_ta);
      m_check_timer.async_wait(boost::bind(&PeerInitiator::run_scheduled_check, initiator_shared_from_this(), boost::placeholders::_1));
    }

    void PeerInitiator::on_ice_complete(boost::system::error_code ec) {
      BOOST_LOG_TRIVIAL(debug) << "Ice complete";
      ice_candidate_collection_complete();
    }

    void PeerInitiator::remote_connection_check_succeeds(const boost::asio::ip::udp::endpoint &remote,
                                                         const boost::asio::ip::udp::endpoint &local,
                                                         std::uint32_t priority, bool use_candidate) {
      boost::upgrade_lock read_lock(m_candidate_mutex);
      // Find if we have this pair. If so, mark it as succeeded.
      // Otherwise, it is a new peer-reflexive candidate

      // Try to find a remote candidate that matches this. Otherwise,
      // it is a new peer-reflexive candidate. It should be added to
      // the remote candidates list, but not paired.
      auto remote_found(std::find_if(m_remote_candidates.begin(), m_remote_candidates.end(),
                                     [&remote] ( const IceCandidate &rc ) {
                                       return remote.address() == rc.addr() &&
                                         remote.port() == rc.port();
                                     }));

      if ( remote_found != m_remote_candidates.end() ) {
        auto found_pair(m_checklist.find_candidate_pair(remote, local));
        if ( found_pair != m_checklist.end() ) {
          if ( use_candidate ) {
            boost::upgrade_to_unique_lock write_lock(read_lock);
            found_pair->set_binding_request_received();

            update_checklist_state();
          } // TODO In the case we got a request without USE canidate, that's the normal nomination strategy
        }
      } else {
        // Peer-reflexive candidate
      }
    }

    void PeerInitiator::connectivity_check_succeeds(const StunTransactionId &tx_id,
                                                    const boost::asio::ip::udp::endpoint &remote,
                                                    const boost::asio::ip::udp::endpoint &mapped_address) {
      boost::upgrade_lock read_lock(m_candidate_mutex);

      // Check to see if any pair sent out a check with this
      // transaction id. If so, and if it's in progress, mark it as
      // successful, and then update state

      auto found_pair(m_checklist.find_check_in_progress(tx_id));
      if ( found_pair != m_checklist.end() ) {
        boost::upgrade_to_unique_lock write_lock(read_lock);
        found_pair->mark_succeeded();

        update_checklist_state();
      }
    }

    void PeerInitiator::update_checklist_state() {
      BOOST_LOG_TRIVIAL(debug) << "Update checklist state";
      m_checklist.update_state();
      if ( m_checklist.has_succeeded() ) {
        BOOST_LOG_TRIVIAL(debug) << "Checklist succeeds";
        m_check_timer.cancel();
        m_checks_running = false;

        auto found_pair(m_checklist.find_nominated());
        assert(found_pair != m_checklist.end());

        for ( auto listener_ptr : m_listeners ) {
          auto listener(listener_ptr.lock());
          if ( listener && listener != found_pair->local()->listener_ptr() ) {
            listener->cancel();
          }
        }

        boost::asio::ip::udp::endpoint r(found_pair->remote()->addr(),
                                         found_pair->remote()->port());
        found_pair->local()->listener().set_nominated(r);

        m_nominated = found_pair->local()->listener_ptr();

        m_listeners.clear();

        m_local_candidates_heap.clear();
        m_remote_candidates_heap.clear();

        m_local_candidates.clear();
        m_remote_candidates.clear();


        // Start SCTP layer
        m_sctp_manager = std::make_shared<PeerSctpManager>(found_pair->local()->listener().data_channel());
        auto acceptor(std::make_shared<PeerSctpManager::acceptor_type>(*m_sctp_manager));

        boost::system::error_code ec;
        // TODO which port?
        acceptor->bind_port(5000, ec);
        if ( ec ) {
          BOOST_LOG_TRIVIAL(error) << "Could not bind acceptor: " << ec;
        }

        acceptor->bind(boost::asio::ip::address(), ec);
        if ( ec ) {
          BOOST_LOG_TRIVIAL(error) << "Could not bind acceptor: " << ec;
        }

        acceptor->listen(2);

        acceptor->async_accept([acceptor, this] (boost::system::error_code ec, PeerSctpManager::socket_type new_socket) {
            if ( ec ) {
              BOOST_LOG_TRIVIAL(error) << "No SCTP association received on this acceptor";
              // TODO what sohuld we do here? Also we should have a timeout waiting for this to accept
            } else {
              m_webrtc_connection = std::make_shared<PeerWebRTCConnection>(std::move(new_socket), true);
              on_data_connection_starts(*m_webrtc_connection);

              if ( m_webrtc_connection->has_delegate() )
                m_webrtc_connection->start();
            }
          });

        m_sctp_manager->start();
      } else if ( m_checklist.has_failed() ) {
        BOOST_LOG_TRIVIAL(error) << "Peer initiator has failed";
      } else
        BOOST_LOG_TRIVIAL(debug) << "Updated checklist state, but the checklist has not succeeded";
    }

    void PeerInitiator::create_answer() {
      // TODO set user_name equal to some kind of flock identifier
      m_session_answer.session_name = m_session_description.session_name;
      m_session_answer.session_version = m_session_description.session_version;

      const auto &incoming_stream(m_session_description.data_stream());

      auto &md(m_session_answer.setup_data_stream(*incoming_stream));
      *std::copy(util::random_iterator<char>(ice_chars, strlen(ice_chars), 4),
                 util::random_iterator<char>(), md->ice_user_fragment) = '\0';
      *std::copy(util::random_iterator<char>(ice_chars, strlen(ice_chars), 24),
                 util::random_iterator<char>(), md->ice_password) = '\0';
      md->ice_trickle = true;

      if ( incoming_stream->is_active_ep )
        md->is_passive_ep = true;
      else if ( incoming_stream->is_passive_ep )
        md->is_active_ep = true;
      else
        BOOST_LOG_TRIVIAL(error) << "SDP with no valid setup";

      std::stringstream data;
      SessionBuilder session_builder(data);
      session_builder.build(m_session_answer);

      answer_session_description(data.str());
    }

    bool PeerInitiator::connectable() const {
      if ( m_checklist.size() == 0 ) return false;
      if ( !m_session_answer.data_stream() ||
           m_session_answer.data_stream()->is_active_ep ) return false;
      return true;
    }

    // Session
    PeerInitiator::PeerSessionDescription::PeerSessionDescription (PeerInitiator &i)
      : m_initiator(i) {
      m_bundled_channels[0] = '\0';
    }

    PeerInitiator::PeerSessionDescription::~PeerSessionDescription () {
    }

    void PeerInitiator::PeerSessionDescription::attribute(const char *name_start, const char *name_end,
                                                          const char *value_start, const char *value_end) {
      // Need to check the group attribute, msid-semantic (perhaps)...
      if ( names_equal(name_start, name_end, "group" ) && value_start && value_end ) {
        static const char bundle_name[] = "BUNDLE ";
        if ( names_start_with(value_start, value_end, bundle_name) ) {
          const char *channels = value_start + strlen(bundle_name);
          m_bundled_channels[0] = '\0';

          *(copy_max(channels, value_end, m_bundled_channels, m_bundled_channels + sizeof(m_bundled_channels) - 1)) = '\0';
        }
      } else
        BOOST_LOG_TRIVIAL(debug) << "Skipping unknown attribute";
    }

    std::unique_ptr<MediaStreamDescription> PeerInitiator::PeerSessionDescription::new_media_stream() {
      return std::make_unique<PeerMediaStreamDescription>(m_initiator);
    }

    void PeerInitiator::PeerSessionDescription::add_media_stream(std::unique_ptr<MediaStreamDescription> d) {
      // Make sure that this media stream is included in our bundle
      std::unique_ptr<PeerMediaStreamDescription> peer_stream(dynamic_cast<PeerMediaStreamDescription *>(d.release()));
      if ( peer_stream && !m_data_stream && peer_stream->media_protocol == MediaStreamDescription::DTLS_SCTP ) {
        BOOST_LOG_TRIVIAL(debug) << "Adding media stream: " << peer_stream->media_type << " with type " << peer_stream->mid;

        // Check that this stream is part of the bundle
        char *bundled_channel_start = m_bundled_channels,
          *bundled_channel_end = m_bundled_channels + sizeof(m_bundled_channels);
        bool channel_in_bundle = false;

        auto is_space_or_zero([] (char c) { return c == ' ' || c == '\0'; });

        for ( char *bundled_channel_cur_end = std::find_if(bundled_channel_start, bundled_channel_end, is_space_or_zero);

              bundled_channel_start < bundled_channel_end;

              bundled_channel_start = bundled_channel_cur_end,
                bundled_channel_cur_end = std::find_if(bundled_channel_start, bundled_channel_end, is_space_or_zero)) {
          BOOST_LOG_TRIVIAL(debug) << "Checking out bundle " << std::string(bundled_channel_start, bundled_channel_cur_end);
          if ( names_equal(bundled_channel_start, bundled_channel_cur_end, peer_stream->mid) ) {
            BOOST_LOG_TRIVIAL(debug) << "Found bundle";
            channel_in_bundle = true;
            break;
          }
        }

        if ( channel_in_bundle )
          m_data_stream = std::move(peer_stream);
      }
    }

    std::unique_ptr<PeerInitiator::PeerMediaStreamDescription> &PeerInitiator::PeerSessionDescription::setup_data_stream(PeerMediaStreamDescription &from) {
      strncpy(m_bundled_channels, from.mid, sizeof(m_bundled_channels) - 1);
      m_bundled_channels[sizeof(m_bundled_channels) - 1] = '\0';

      m_found_data_channel = true;

      m_data_stream = std::make_unique<PeerInitiator::PeerMediaStreamDescription>(m_initiator);
      std::copy(from.mid, from.mid + sizeof(from.mid), m_data_stream->mid);
      std::copy(from.media_type, from.media_type + sizeof(from.media_type), m_data_stream->media_type);
      std::copy(from.media_format, from.media_format + sizeof(from.media_format), m_data_stream->media_format);
      m_data_stream->port_start = from.port_start;
      m_data_stream->media_protocol = MediaStreamDescription::DTLS_SCTP;

      return m_data_stream;
    }

    void PeerInitiator::PeerSessionDescription::serialize_attributes(ISessionAttributes &a) {
      std::stringstream bundle;
      bundle << "BUNDLE " << m_bundled_channels;
      a.attribute("group", bundle.str().c_str());
      a.attribute("msid-semantic", " WMS");
    }

    void PeerInitiator::PeerSessionDescription::serialize_streams(ISessionStreams &b) {
      if ( m_data_stream )
        b.stream(*m_data_stream);
    }

    bool PeerInitiator::verify_peer_cert(DTLSChannel *c, const X509Certificate &peer_cert) {
      std::uint8_t peer_fingerprint[SHA256_DIGEST_LENGTH];
      if ( m_session_description.data_stream() &&
           m_session_description.data_stream()->has_fingerprint &&
           peer_cert.sha256_fingerprint(peer_fingerprint) ) {

        const std::uint8_t *expecting(m_session_description.data_stream()->ssl_cert_fingerprint);
        return std::equal(peer_fingerprint, peer_fingerprint + SHA256_DIGEST_LENGTH,
                          expecting);
      } else {
        BOOST_LOG_TRIVIAL(error) << "Could not verify peer certificate";
        return false;
      }
    }

    const X509Certificate &PeerInitiator::ssl_certificate() const {
      return m_local_cert;
    }

    // Media stream
    PeerInitiator::PeerMediaStreamDescription::PeerMediaStreamDescription(PeerInitiator &i)
      : ice_trickle(false), is_active_ep(false), is_passive_ep(false), has_fingerprint(false),
        m_initiator(i) {
      mid[0] = '\0';
    }

    PeerInitiator::PeerMediaStreamDescription::~PeerMediaStreamDescription() {
    }

    void PeerInitiator::PeerMediaStreamDescription::attribute(const char *nms, const char *nme,
                                                              const char *vls, const char *vle) {
      if ( names_equal(nms, nme, "mid") && vls && vle) {
        *copy_max(vls, vle, mid, mid + sizeof(mid) - 1) = '\0';
      } else if ( names_equal(nms, nme, "ice-options") && vls && vle ) {
        if ( names_equal(vls, vle, "trickle") )
          ice_trickle = true;
      } else if ( names_equal(nms, nme, "ice-ufrag") && (vle - vls) >= 4 && std::size_t(vle - vls) < (sizeof(ice_user_fragment) - 1)) {
        *std::copy(vls, vle, ice_user_fragment) = '\0';
      } else if ( names_equal(nms, nme, "ice-pwd") && (vle - vls) > 22 && std::size_t(vle - vls) < (sizeof(ice_password) - 1)) {
        *std::copy(vls, vle, ice_password) = '\0';
      } else if ( names_equal(nms, nme, "setup") && vls && vle ) {
        if ( names_equal(vls, vle, "actpass") )
          is_active_ep = is_passive_ep = true;
        else if ( names_equal(vls, vle, "active") )
          is_active_ep = true;
        else if ( names_equal(vls, vle, "passive") )
          is_passive_ep = true;
      } else if ( names_equal(nms, nme, "fingerprint") && vls && vle &&
                  (vle - vls) > 8 ) {
        // Parse fingerprint
        static const char sha256_prefix[] = "sha-256 ";
        if ( std::equal(sha256_prefix, sha256_prefix + 8, vls) ) {
          const char *cur(vls + 8);
          for ( ; isspace(*cur) && cur != vle; cur++ );

          char fingerprint[sizeof(ssl_cert_fingerprint)];
          for ( std::size_t i = 0; i < sizeof(fingerprint); ++i ) {
            if ( cur >= vle ) return;
            if ( cur[0] == ':' ) ++cur;

            if ( (vle - cur) >= 2 && isxdigit(cur[0]) && isxdigit(cur[1])) {
              fingerprint[i] = hex_value(cur[0]) * 0x10 + hex_value(cur[1]);

              cur += 2;
            } else
              return;
          }

          std::copy(fingerprint, fingerprint + sizeof(fingerprint), ssl_cert_fingerprint);
          has_fingerprint = true;
        }
      }
    }

    void PeerInitiator::PeerMediaStreamDescription::serialize_attributes(ISessionAttributes &b) {
      b.attribute("ice-ufrag", ice_user_fragment);
      b.attribute("ice-pwd", ice_password);
      if ( ice_trickle )
        b.attribute("ice-options", "trickle");

      std::uint8_t fingerprint[SHA256_DIGEST_LENGTH];
      if ( m_initiator.local_cert().sha256_fingerprint(fingerprint) ) {
        std::stringstream s;
        s << "sha-256";
        for ( std::size_t i = 0; i < sizeof(fingerprint); ++i ){
          s << (i == 0 ? ' ' : ':') << std::hex << std::setfill('0') << std::setw(2) << ((std::uint16_t)fingerprint[i]);
        }

        BOOST_LOG_TRIVIAL(debug) << "Got fingerprint " << s.str();
        b.attribute("fingerprint", s.str().c_str());
      } else
        BOOST_LOG_TRIVIAL(debug) << "Could not get certificate fingerprint";

      if ( is_active_ep && is_passive_ep )
        b.attribute("setup", "actpass");
      else if ( is_active_ep )
        b.attribute("setup", "active");
      else if ( is_passive_ep )
        b.attribute("setup", "passive");

      b.attribute("mid", mid);
      b.attribute("sctpmap", "5000 webrtc-datachannel 1024");
    }

    // IceConnectivityListener
    IceConnectivityListener::IceConnectivityListener(boost::asio::io_service &svc,
                                                     const boost::asio::ip::udp::endpoint &ep,
                                                     const PeerInitiator::PeerMediaStreamDescription &remote,
                                                     const PeerInitiator::PeerMediaStreamDescription &local,
                                                     std::shared_ptr<PeerInitiator> c)
      : m_service(svc), m_initiator(c),
        m_socket(svc, ep.protocol()),
        m_local(ep), m_nominated(false),
        m_dtls_server(*c, boost::bind(&IceConnectivityListener::signal_needs_send, this)),
        m_offer(remote), m_answer(local) {

      m_socket.set_option(boost::asio::ip::udp::socket::reuse_address(true));
      m_socket.bind(ep);
    }

    IceConnectivityListener::~IceConnectivityListener() {
      cancel();
    }

    void IceConnectivityListener::async_start() {
      boost::unique_lock l(m_socket_mutex);
      m_socket.async_receive_from
        (boost::asio::buffer(m_recvd_datagram_buffer, NETWORK_DATAGRAM_SIZE), m_remote,
         boost::bind(&IceConnectivityListener::do_serve, shared_from_this(),
                     boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
    }

    void IceConnectivityListener::do_serve(boost::system::error_code ec, std::size_t bytes_recvd) {
      if ( ec ) {
        BOOST_LOG_TRIVIAL(error) << "IceConnectivityListener on " << m_local << " fails: " << ec;
      } else {
        m_bytes_recvd = bytes_recvd;

        if ( bytes_recvd < sizeof(m_stun_request) && m_stun_request.type() == StunMsgHdr::Binding )
          serve_binding_request();
        else if ( bytes_recvd < sizeof(m_stun_request) && m_stun_request.type() == StunMsgHdr::BindingResponse ) {
          process_binding_response();
        } else {
          non_stun();
        }
      }
    }

    void IceConnectivityListener::set_nominated(const boost::asio::ip::udp::endpoint &remote) {
      boost::unique_lock l(m_nomination_mutex);

      if ( !m_nominated ) {
        m_nominated = true;
        m_nominated_remote = remote;

        // TODO Set the remote address
        reset_dtls();
      }
    }

    void IceConnectivityListener::reset_dtls() {
      //DTLSServer s(*m_initiator);
      //std::swap(m_dtls_server, s);
    }

    void IceConnectivityListener::send_datagram(const boost::asio::const_buffer &buffer,
                                                std::function<void(boost::system::error_code, std::size_t)> completion) {
      BOOST_LOG_TRIVIAL(debug) << "Sending datagram";
      m_service.post(boost::bind(completion, boost::system::error_code(), 0));
    }

    void IceConnectivityListener::send_connectivity_check(const PeerInitiator::CandidatePair &p,
                                                          std::function<void(boost::system::error_code)> completion) {
      BOOST_LOG_TRIVIAL(debug) << "Starting connectivity check";
      IceCandidate potential_prflx;
      potential_prflx.component_id(1);
      potential_prflx.transport(IceCandidate::UDP);
      potential_prflx.type(IceCandidate::prflx);

      boost::unique_lock l(m_socket_mutex);

      m_conn_check_request = StunMsgHdr(p.check_tx_id(), StunMsgHdr::Binding);
      m_conn_check_request.add_attr<UsernameData>(m_offer.ice_user_fragment, m_answer.ice_user_fragment);
      m_conn_check_request.add_attr<PriorityData>(potential_prflx.recommended_priority(0));
      m_conn_check_request.add_attr<IceControlled>(m_initiator->tie_breaker());

      MessageIntegrityData &msg_integrity(m_conn_check_request.add_attr<MessageIntegrityData>());
      if ( !m_conn_check_request.message_integrity(m_offer.ice_password,
                                                   strnlen(m_offer.ice_password, sizeof(m_offer.ice_password)),
                                                   msg_integrity.hmac_fingerprint) ) {
        BOOST_LOG_TRIVIAL(error) << "Could not calculate HMAC-SHA1";
        return;
      }

      FingerprintData &fg(m_conn_check_request.add_attr<FingerprintData>());
      fg.fingerprint(m_conn_check_request.crc_fingerprint());

      boost::asio::ip::udp::endpoint remote_ep(p.remote_candidate().addr(), p.remote_candidate().port());
      BOOST_LOG_TRIVIAL(debug) << "Sending connectivity check to " << remote_ep;
      m_socket.async_send_to(m_conn_check_request.as_asio_send_buffer(), remote_ep,
                             boost::bind(completion, boost::asio::placeholders::error));
    }

    void IceConnectivityListener::non_stun() {
      BOOST_LOG_TRIVIAL(debug) << "Ice connectivity listener on " << m_local << " receives non-stun packet";
      boost::shared_lock nomination_l(m_nomination_mutex);
      if ( m_nominated && m_remote == m_nominated_remote ) {
        m_dtls_server.push_datagram(boost::asio::buffer(m_recvd_datagram_buffer, m_bytes_recvd));

        // Flush datagrams now
        flush_dtls_datagrams(boost::bind(&IceConnectivityListener::response_sent, shared_from_this(), boost::system::error_code()));
      } else {
        //        nomination_l.unlock();

        response_sent(boost::system::error_code());
      }
    }

    void IceConnectivityListener::signal_needs_send() {
      flush_dtls_datagrams(boost::bind(&IceConnectivityListener::all_sent, shared_from_this()));
    }

    void IceConnectivityListener::all_sent() {
      BOOST_LOG_TRIVIAL(info) << "DTLS packets sent";
    }

    void IceConnectivityListener::flush_dtls_datagrams(std::function<void()> completion) {
      if ( m_dtls_server.has_outgoing_datagram() ) {
        BOOST_LOG_TRIVIAL(debug) << "DTLS has outgoing datagram";
        boost::unique_lock socket_l(m_socket_mutex);
        boost::shared_lock nomination_l(m_nomination_mutex);

        auto shared(shared_from_this());
        m_socket.async_send_to(m_dtls_server.next_outgoing_datagram(), m_nominated_remote,
                               [completion, shared] ( boost::system::error_code ec, std::size_t b ) {
                                 if ( ec ) {
                                   BOOST_LOG_TRIVIAL(error) << "Error writing data gram " << ec;
                                 } else
                                   shared->flush_dtls_datagrams(completion);
                               });
      } else {
        BOOST_LOG_TRIVIAL(debug) << "DTLS has no outgoing datagram";
        m_service.post(completion);
      }
    }

    void IceConnectivityListener::serve_binding_request() {
      BOOST_LOG_TRIVIAL(debug) << "Received binding request from " << m_remote << " at " << m_local;

      bool user_found(false), is_controlled(false), fingerprinted(false),
        integrity_verified(false), use_candidate(false);
      std::uint32_t prio(0);
      // TODO we're supposed to return invalid responses here
      for ( StunAttr &attr : m_stun_request ) {
        if ( fingerprinted ) {
          non_stun();
          return;
        }

        switch ( attr.type() ) {
        case StunAttr::USE_CANDIDATE: {
          use_candidate = true;
          break;
        }
        case StunAttr::PRIORITY: {
          prio = attr.data<PriorityData>().prio();
          break;
        }
        case StunAttr::USERNAME: {
          if ( attr.length() >= 9 ) {
            if ( attr.data<UsernameData>().is_valid(m_answer.ice_user_fragment, m_offer.ice_user_fragment) ) {
              user_found = true;
            } else {
              send_error_response(401, "Unauthorized");
              return;
            }
          }
          break;
        }
        case StunAttr::ICE_CONTROLLING: {
          is_controlled = true;
          // TODO use tie breaker
          break;
        }
        case StunAttr::ICE_CONTROLLED: {
          BOOST_LOG_TRIVIAL(debug) << "Got ICE controlled in binding request";
          send_error_response(487, "Role Conflict");
          return;
        }
        case StunAttr::FINGERPRINT: {
          if ( attr.length() == 4 ) {
            if ( attr.data<FingerprintData>().fingerprint() != m_stun_request.crc_fingerprint() ) {
              BOOST_LOG_TRIVIAL(debug) << "ICE request rejected due to fingerprint: " << std::hex << attr.data<FingerprintData>().fingerprint() << " " << std::hex << m_stun_request.crc_fingerprint();
              // Badly fingerprinted messages are likely not STUN
              // messages. So return nothing but pass to the next
              // layer
              non_stun();
              return;
            } else {
              fingerprinted = true;
              break;
            }
          } else {
            send_error_response(400, "Bad Request");
            return;
          }
        }
        case StunAttr::MESSAGE_INTEGRITY: {
          if ( attr.length() == 20 ) {
            const MessageIntegrityData &expected(attr.data<MessageIntegrityData>());

            if ( expected.verify_message(m_stun_request, m_answer.ice_password, strnlen(m_answer.ice_password, sizeof(m_answer.ice_password))) )
              integrity_verified = true;
            else {
              send_error_response(401, "Unauthorized");
              BOOST_LOG_TRIVIAL(debug) << "Message not verified";
              return;
            }

            break;
          } else {
            send_error_response(400, "Bad Request");
            return;
          }
        }
        default: break;
        }
      }

      if ( !fingerprinted ) {
        non_stun();
        return;
      }

      if ( user_found && integrity_verified && is_controlled ) {
        m_stun_response = StunMsgHdr(m_stun_request.tx_id(), StunMsgHdr::BindingResponse);
        m_stun_response.add_attr<XorMappedAddressData>(m_remote, m_stun_response.tx_id());

        MessageIntegrityData &integrity(m_stun_response.add_attr<MessageIntegrityData>());
        if ( !m_stun_response.message_integrity(m_answer.ice_password,
                                                strnlen(m_answer.ice_password, sizeof(m_answer.ice_password)),
                                                integrity.hmac_fingerprint) ) {
          send_error_response(500, "Internal Error");
          return;
        }

        FingerprintData &fg(m_stun_response.add_attr<FingerprintData>());
        fg.fingerprint(m_stun_response.crc_fingerprint());

        m_initiator->remote_connection_check_succeeds(m_remote, m_local, prio, use_candidate);

        send_response();

        return;
      } else {
        send_error_response(400, "Bad Request");
        return;
      }
    }

    void IceConnectivityListener::process_binding_response() {
      BOOST_LOG_TRIVIAL(debug) << "IceConnectivityListener: received bindingresponse on " << m_remote;
      bool fingerprinted(false), message_verified(false), got_address(false);
      boost::asio::ip::udp::endpoint mapped_ep;
      for ( StunAttr &attr: m_stun_request ) {
        if ( fingerprinted ) { non_stun(); return; }

        switch ( attr.type() ) {
        case StunAttr::FINGERPRINT: {
          if ( attr.length() == 4 ) {
            if ( attr.data<FingerprintData>().fingerprint() != m_stun_request.crc_fingerprint() ) {
              non_stun();
              return;
            } else
              fingerprinted = true;
          }
          break;
        }
        case StunAttr::MESSAGE_INTEGRITY: {
          if ( attr.length() == 20 ) {
            if ( !attr.data<MessageIntegrityData>().verify_message(m_stun_request,
                                                                  m_offer.ice_password,
                                                                  strnlen(m_offer.ice_password, sizeof(m_offer.ice_password))) )
              goto done;
            else
              message_verified = true;
          }
          break;
        }
        case StunAttr::MAPPED_ADDRESS:
        case StunAttr::XOR_MAPPED_ADDRESS: {
          bool do_xor(attr.type() == StunAttr::XOR_MAPPED_ADDRESS);
          auto mapped_addr(attr.data<MappedAddressData>().ip_address(do_xor, m_stun_request.tx_id()));
          auto mapped_port(attr.data<MappedAddressData>().port(do_xor));
          boost::asio::ip::udp::endpoint new_mapped_addr(mapped_addr, mapped_port);

          if ( !got_address ) {
            got_address = true;
            mapped_ep = new_mapped_addr;
          } else if ( mapped_ep != new_mapped_addr ) {
            BOOST_LOG_TRIVIAL(error) << "Ignoring response because mapped addresses do not match";
            goto done;
          }
          break;
        }
        default: break;
        }
      }

      if ( fingerprinted && message_verified && got_address ) {
        BOOST_LOG_TRIVIAL(debug) << "Processing binding response: update state";
        m_initiator->connectivity_check_succeeds(m_stun_request.tx_id(),
                                                 m_remote, mapped_ep);
      }

    done:
      response_sent(boost::system::error_code());
    }

    void IceConnectivityListener::send_response() {
      boost::unique_lock l(m_socket_mutex);
      m_socket.async_send_to(m_stun_response.as_asio_send_buffer(), m_remote,
                             boost::bind(&IceConnectivityListener::response_sent, shared_from_this(),
                                         boost::asio::placeholders::error));
    }

    void IceConnectivityListener::response_sent(boost::system::error_code ec) {
      if ( ec ) {
        BOOST_LOG_TRIVIAL(error) << "Error while sending ICE response: " << ec;
      } else {
        boost::unique_lock l(m_socket_mutex);
        m_socket.async_receive_from(m_stun_request.as_asio_recv_buffer(), m_remote,
                                    boost::bind(&IceConnectivityListener::do_serve, shared_from_this(),
                                                boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
      }
    }

    void IceConnectivityListener::send_error_response(std::uint16_t err_code, const char *msg) {
      m_stun_response = StunMsgHdr(m_stun_request.tx_id(), StunMsgHdr::BindingError);
      m_stun_response.add_attr<ErrorCodeData>(err_code, msg);
      send_response();
    }

    void IceConnectivityListener::cancel() {
      m_socket.cancel();
    }
  }
}
