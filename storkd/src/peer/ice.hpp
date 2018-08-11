#ifndef __stork_peer_ice_HPP__
#define __stork_peer_ice_HPP__

#include <boost/asio.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <list>
#include <unordered_set>

#include "../uri.hpp"
#include "stun.hpp"

namespace stork {
  namespace peer {
    enum IceCandidatePairState {
      invalid,
      waiting,
      in_progress,
      succeeded,
      frozen,
      failed
    };

    class IceCandidate;

    template<typename CandidatePtr>
    const IceCandidate &ice_candidate(const CandidatePtr &p) { return p; }

    // By default, we are always controlled
    template<typename CandidatePtr1, typename CandidatePtr2, bool Controlled=true>
    class IceCandidatePair {
    public:
      using remote_type = CandidatePtr1;
      using local_type = CandidatePtr2;

      IceCandidatePair(CandidatePtr1 r, CandidatePtr2 l)
        : m_remote(r), m_local(l), m_priority(0), m_binding_req_recvd(false), m_state(IceCandidatePairState::invalid) {
        std::uint64_t controlling_priority(Controlled ? ice_candidate(*m_remote).priority() : ice_candidate(*m_local).priority());
        std::uint64_t controlled_priority(Controlled ? ice_candidate(*m_local).priority() : ice_candidate(*m_remote).priority());

        m_priority = (std::min(controlling_priority, controlled_priority) << 32) +
          2 * std::max(controlling_priority, controlled_priority) +
          (controlling_priority > controlled_priority ? 1 : 0);
      }
      IceCandidatePair() : m_priority(0), m_binding_req_recvd(false), m_state(IceCandidatePairState::invalid) { }

      inline CandidatePtr1 remote() const { return m_remote; }
      inline CandidatePtr2 local() const { return m_local; }

      inline const IceCandidate &remote_candidate() const { return ice_candidate(*m_remote); }
      inline const IceCandidate &local_candidate() const { return ice_candidate(*m_local); }

      inline bool invalid() const { return m_state == IceCandidatePairState::invalid; }
      inline bool valid() const { return !invalid(); }
      inline bool nominated() const { return m_binding_req_recvd && m_state == succeeded; }
      inline IceCandidatePairState state() const { return m_state; }
      inline std::uint64_t priority() const { return m_priority; }
      inline const StunTransactionId &check_tx_id() const { return m_check_tx; }

      inline void reprioritize(std::uint64_t p) { m_priority = p; }

      void invalidate() {
        m_state = IceCandidatePairState::invalid;
        m_remote = CandidatePtr1();
        m_local = CandidatePtr2();
      }

      inline bool is_redundant_with(const IceCandidatePair<CandidatePtr1, CandidatePtr2, Controlled> &p) const {
        return p.m_remote == m_remote && p.m_local == m_local;
      }

      inline bool is_frozen_or_waiting() const {
        return m_state == IceCandidatePairState::frozen || m_state == IceCandidatePairState::waiting;
      }
      inline bool is_in_progress() const {
        return m_state == IceCandidatePairState::in_progress;
      }


      inline bool failed() const {
        return m_state == IceCandidatePairState::failed;
      }

      inline void start_wait() { m_state = waiting; }
      inline void start_check(const StunTransactionId &tx) {
        m_state = in_progress;
        m_check_tx = tx;
      }
      inline void mark_succeeded() {
        m_state = succeeded;
      }

      inline void set_binding_request_received() {
        m_binding_req_recvd = true;
      }

      bool well_formed() const {
        // According to https://tools.ietf.org/html/rfc5245#page-31
        //
        // A candidate pair is formed if IP versions match and the component ids are the same

        bool ip_versions_match =
          (ice_candidate(*m_remote).addr().is_v6() && ice_candidate(*m_local).addr().is_v6()) ||
          (ice_candidate(*m_remote).addr().is_v4() && ice_candidate(*m_local).addr().is_v4());

        bool component_ids_match =
          ice_candidate(*m_remote).component_id() == ice_candidate(*m_local).component_id();

        BOOST_LOG_TRIVIAL(debug) << "Check well-formedness " << ice_candidate(*m_remote).addr() << " " << ice_candidate(*m_local).addr() << " " << (int) ice_candidate(*m_remote).component_id() << " " << (int)ice_candidate(*m_local).component_id();

        return component_ids_match && ip_versions_match;
      }

    private:
      CandidatePtr1 m_remote;
      CandidatePtr2 m_local;
      std::uint64_t m_priority;
      bool m_binding_req_recvd;
      IceCandidatePairState m_state;

      StunTransactionId m_check_tx;
    };

    class IceCandidate {
    public:
      IceCandidate();
      IceCandidate(const IceCandidate &c);
      enum Transport {
        UDP
      };

      enum CandidateType {
        host, srflx, prflx, relay
      };

      inline const char *foundation() const { return m_foundation; }
      inline std::uint8_t component_id() const { return m_component_id; }
      inline Transport transport() const { return m_transport; }
      inline std::uint32_t priority() const { return m_priority; }
      inline CandidateType type() const { return m_type; }

      inline const boost::asio::ip::address &addr() const { return m_addr; }
      inline std::uint16_t port() const { return m_port; }

      inline const boost::asio::ip::address &raddr() const { return m_raddr; }
      inline std::uint16_t rport() const { return m_rport; }

      void foundation(const char *foundation);
      inline void component_id(std::uint8_t id) { m_component_id = id; }
      inline void transport(IceCandidate::Transport t) { m_transport = t; }
      inline void priority(std::uint32_t p) { m_priority = p; }
      inline void type(IceCandidate::CandidateType t) { m_type = t; }
      inline void addr(const boost::asio::ip::address &newaddr) { m_addr = newaddr; }
      inline void port(std::uint16_t p) { m_port = p; }
      inline void raddr(const boost::asio::ip::address &newaddr) { m_raddr = newaddr; }
      inline void rport(std::uint16_t p) { m_rport = p; }

      bool is_redundant(const IceCandidate &c) const;

      IceCandidate base() const;

      std::string as_sdp_string() const;

      std::uint32_t recommended_priority(std::uint16_t local_preference) const;

      void swap(IceCandidate &c);

      bool from_string(const std::string &c);

      template<typename RemoteIterator, typename LocalIterator, typename OutputIterator,
               typename Pair = typename OutputIterator::container_type::value_type>
      static void form_candidate_pairs(RemoteIterator rbegin, RemoteIterator rend,
                                       LocalIterator lbegin, LocalIterator lend,
                                       OutputIterator out) {
        for ( auto r(rbegin); r != rend; r++ )
          for ( auto l(lbegin); l != lend; l++ ) {
            if ( ((ice_candidate(*r).addr().is_v6() && ice_candidate(*l).addr().is_v6()) ||
                  (ice_candidate(*r).addr().is_v4() && ice_candidate(*l).addr().is_v4())) ||
                 ice_candidate(*l).component_id() == ice_candidate(*r).component_id() ) {
              Pair p(r,l);
              *out = p;
              out ++;
            }
          }
      }

    protected:
      char m_foundation[33];
      std::uint8_t m_component_id;
      Transport m_transport;
      std::uint32_t m_priority;
      CandidateType m_type;

      boost::asio::ip::address m_addr, m_raddr;
      std::uint16_t m_port, m_rport;
    };

    // A collector for ice candidates
    class IceCandidateCollector {
    public:
      IceCandidateCollector(boost::asio::io_service &svc);

      void add_ice_server(const uri::Uri &uri);

      void async_collect_candidates();

      inline boost::random::mt19937 &gen() { return m_gen; }

    protected:
      virtual void on_receive_ice_candidate(const IceCandidate &c) =0;
      virtual void on_ice_complete(boost::system::error_code ec) =0;

      virtual std::shared_ptr<IceCandidateCollector> base_shared_from_this() =0;

    private:
      // m_completion_mutex should be held
      void flag_error(boost::system::error_code m_completion_error);

      void collect_candidate(const IceCandidate &c);
      void end_of_candidates();

      void start_stun();

      boost::asio::io_service &m_service;
      boost::asio::io_service::strand m_cb_strand;

      boost::mutex m_completion_mutex;
      boost::system::error_code m_completion_error;
      std::size_t m_stun_resolution_complete;

      boost::asio::ip::udp::resolver m_host_resolver;
      std::list< std::pair<std::string, std::uint16_t> > m_stun_servers;

      boost::random::mt19937 m_gen;

      friend class StunCollector;
    };
  }
}

#endif
