#ifndef __stork_peer_initiator_HPP__
#define __stork_peer_initiator_HPP__

#include <boost/asio.hpp>
#include <boost/thread/shared_mutex.hpp>
#include <vector>

#include "checklist.hpp"
#include "../appliance.hpp"
#include "../util/array.hpp"
#include "session.hpp"
#include "ice.hpp"
#include "certificate.hpp"
#include "dtls.hpp"
// #include "push_pull_socket.hpp"

namespace stork {
  namespace peer {
    class IceConnectivityListener;

    class LocalIceCandidate {
    public:
      inline LocalIceCandidate(std::shared_ptr<IceConnectivityListener> l,
                               const IceCandidate &c)
        : m_listener(l), m_candidate(c) {
      }
      inline LocalIceCandidate() { }

      inline const IceCandidate &candidate() const { return m_candidate; }
      inline std::shared_ptr<IceConnectivityListener> listener_ptr() const { return m_listener; }
      inline IceConnectivityListener &listener() const { return *m_listener; }

      inline void replace_candidate(const IceCandidate &c) { m_candidate = c; }
    private:
      std::shared_ptr<IceConnectivityListener> m_listener;
      IceCandidate m_candidate;
    };

    class PeerInitiator : public IceCandidateCollector,
                          public DTLSContext {
    public:
      PeerInitiator(boost::asio::io_service &service);
      virtual ~PeerInitiator();

      boost::asio::io_service &service() const;

      void set_session_description(const std::string &sdp);
      void add_ice_candidate(const std::string &ice);

      inline bool valid() const { return !m_received_sdp || m_received_sdp_valid; }
      bool connectable() const;
      inline const X509Certificate &local_cert() const { return m_local_cert; }

      inline std::uint64_t tie_breaker() const { return m_tie_breaker; }

      virtual void answer_session_description(const std::string &sdp) =0;
      virtual void send_ice_candidate(const std::string &ice_candidate) =0;
      virtual void ice_candidate_collection_complete() =0;
      virtual void on_data_connection_starts(DTLSChannel &chan) =0;

      void remote_connection_check_succeeds(const boost::asio::ip::udp::endpoint &remote,
                                            const boost::asio::ip::udp::endpoint &local,
                                            std::uint32_t priority, bool use_candidate);
      void connectivity_check_succeeds(const StunTransactionId &tx_id,
                                       const boost::asio::ip::udp::endpoint &remote,
                                       const boost::asio::ip::udp::endpoint &mapped_address);

      // PushPullSocket new_socket();

      using IceCandidates = util::fixed_array<IceCandidate, 8>;
      using LocalIceCandidates = util::fixed_array< LocalIceCandidate, 8 >;
      using CandidatePair = IceCandidatePair<IceCandidates::iterator, LocalIceCandidates::iterator>;

      class PeerMediaStreamDescription : public MediaStreamDescription {
      public:
        PeerMediaStreamDescription(PeerInitiator &i);
        virtual ~PeerMediaStreamDescription();

        char mid[32];
        bool ice_trickle   : 1;
        bool is_active_ep  : 1;
        bool is_passive_ep : 1;
        bool has_fingerprint : 1;

        std::uint8_t ssl_cert_fingerprint[SHA256_DIGEST_LENGTH];
        char ice_user_fragment[256];
        char ice_password[256];

        PeerInitiator &m_initiator;

      private:
        virtual void attribute(const char *nms, const char *nme,
                               const char *vls, const char *vle);
        virtual void serialize_attributes(ISessionAttributes &b);
      };

      class PeerSessionDescription : public SessionDescription {
      public:
        PeerSessionDescription(PeerInitiator &i);
        virtual ~PeerSessionDescription();

        bool valid() const;

        inline const std::unique_ptr<PeerMediaStreamDescription> &data_stream() const { return m_data_stream; }
        std::unique_ptr<PeerMediaStreamDescription> &setup_data_stream(PeerMediaStreamDescription &from);

      protected:
        virtual void attribute(const char *name_start, const char *name_end,
                               const char *value_start, const char *value_end);
        virtual std::unique_ptr<MediaStreamDescription> new_media_stream();
        virtual void add_media_stream(std::unique_ptr<MediaStreamDescription> d);

        virtual void serialize_attributes(ISessionAttributes &b);
        virtual void serialize_streams(ISessionStreams &b);

        PeerInitiator &m_initiator;

        bool m_found_data_channel;
        char m_bundled_channels[64]; // TODO size increase?

        std::unique_ptr<PeerMediaStreamDescription> m_data_stream;
      };

    protected:
      virtual void on_receive_ice_candidate(const IceCandidate &c);
      virtual void on_ice_complete(boost::system::error_code ec);

      virtual bool verify_peer_cert(DTLSChannel *c, const X509Certificate &cert) override;
      virtual const X509Certificate &ssl_certificate() const override;

      virtual std::shared_ptr<PeerInitiator> initiator_shared_from_this() =0;
    private:

      void create_answer();
      std::shared_ptr<IceConnectivityListener> start_connectivity(const boost::unique_lock<boost::upgrade_mutex> &l, const IceCandidate &local_candidate);
      void start_checks();
      void send_checks();
      void run_scheduled_check(boost::system::error_code ec);
      void conn_check_completes(CandidatePair &pair, boost::system::error_code ec);
      void update_checklist_state();

      boost::asio::io_service &m_service;

      std::uint64_t m_tie_breaker;

      bool m_received_sdp, m_received_sdp_valid;
      PeerSessionDescription m_session_description, m_session_answer;

      X509Certificate m_local_cert;

      // Accept at most 8 candidates for now
      boost::upgrade_mutex m_candidate_mutex;
      IceCandidates m_remote_candidates;
      util::fixed_array< IceCandidates::iterator, IceCandidates::max_size > m_remote_candidates_heap;

      LocalIceCandidates m_local_candidates;
      util::fixed_array< LocalIceCandidates::iterator, LocalIceCandidates::max_size > m_local_candidates_heap;

      util::fixed_array<std::weak_ptr<IceConnectivityListener>, 8> m_listeners;

      // TODO, we may want to free this if possible, after we have successfully connected
      IceCheckList< CandidatePair, 100 > m_checklist;

      boost::asio::deadline_timer m_check_timer;
      boost::posix_time::time_duration m_check_ta;
      bool m_checks_running;

      // The currently nominated connection
      std::shared_ptr<IceConnectivityListener> m_nominated;
      //      std::shared_ptr<PushPullAdaptor> m_data_stream_adaptor;
    };

    template<>
    inline const IceCandidate &ice_candidate<LocalIceCandidate>(const LocalIceCandidate &c) {
      return c.candidate();
    }

    // IceConnectivityListener
    /**
     * This class listens on a UDP endpoint for binding requests for local sockets
     */
    class IceConnectivityListener : public std::enable_shared_from_this<IceConnectivityListener> {
    public:
      IceConnectivityListener(boost::asio::io_service &svc,
                              const boost::asio::ip::udp::endpoint &ep,
                              const PeerInitiator::PeerMediaStreamDescription &remote,
                              const PeerInitiator::PeerMediaStreamDescription &local,
                              std::shared_ptr<PeerInitiator> c);
      ~IceConnectivityListener();

      void async_start();

      void cancel();
      void send_connectivity_check(const PeerInitiator::CandidatePair &p,
                                   std::function<void(boost::system::error_code)> completion);

      void set_nominated(const boost::asio::ip::udp::endpoint &n);

      inline const boost::asio::ip::udp::endpoint &local_endpoint() const { return m_local; }

      void send_datagram(const boost::asio::const_buffer &buffer,
                                 std::function<void(boost::system::error_code, std::size_t)> completion);

      inline DTLSChannel &data_channel() { return m_dtls_server; }

    private:
      void do_serve(boost::system::error_code ec, std::size_t bytes_recvd);
      void serve_binding_request();
      void process_binding_response();
      void non_stun();
      void signal_needs_send();
      void all_sent();

      void reset_dtls();
      void flush_dtls_datagrams(std::function<void()> completion);

      void send_error_response(std::uint16_t err_code, const char *msg);
      void send_response();
      void response_sent(boost::system::error_code ec);

      boost::asio::io_service &m_service;
      std::shared_ptr<PeerInitiator> m_initiator;

      boost::shared_mutex m_socket_mutex;
      boost::asio::ip::udp::socket m_socket;

      boost::asio::ip::udp::endpoint m_local, m_remote;

      StunMsgHdr m_stun_response;
      StunMsgHdr m_conn_check_request;

      boost::shared_mutex m_nomination_mutex; // Always lock after m_socket_mutex
      bool m_nominated;
      boost::asio::ip::udp::endpoint m_nominated_remote;

      DTLSServer m_dtls_server;

      const PeerInitiator::PeerMediaStreamDescription &m_offer, &m_answer;

      static constexpr std::size_t NETWORK_DATAGRAM_SIZE = 8192;

      std::size_t m_bytes_recvd;
      union {
        StunMsgHdr m_stun_request;
        char m_recvd_datagram_buffer[NETWORK_DATAGRAM_SIZE];
      };
    };
  }
}

#endif
