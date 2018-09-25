#include <boost/log/trivial.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/bind.hpp>
#include <functional>
#include <sys/types.h>
#include <ifaddrs.h>

#include "ice.hpp"

namespace stork {
  namespace peer {
    // IceCandidateParser
    class IceCandidateParser {
    public:
      IceCandidateParser(const std::string &s)
        : m_valid(true), m_data(s), m_index(0) {
      }

      bool parse(IceCandidate &c) {
        char foundation[33];
        if ( !expect("candidate:") ) return false;

        if ( !parse_field(foundation, sizeof(foundation)) ) return false;
        c.foundation(foundation);

        std::uint8_t component_id;
        if ( !parse_decimal(component_id) ) return false;
        c.component_id(component_id);

        if ( !expect("udp ") ) return false;
        c.transport(IceCandidate::UDP);

        std::uint32_t priority;
        if ( !parse_decimal(priority) ) return false;
        c.priority(priority);

        char ip_address[65];
        if ( !parse_field(ip_address, sizeof(ip_address)) ) return false;

        boost::system::error_code ec;
        c.addr(boost::asio::ip::address::from_string(ip_address, ec));
        if ( ec ) return false;

        std::uint16_t port;
        if ( !parse_decimal(port) ) return false;
        c.port(port);

        if ( !expect("typ ") ) return false;

        if ( peek_next("host ") ) {
          expect("host ");
          c.type(IceCandidate::host);
        } else if ( peek_next("srflx ") ) {
          expect("srflx ");
          c.type(IceCandidate::srflx);
        } else if ( peek_next("prflx ") ) {
          expect("prflx ");
          c.type(IceCandidate::prflx);
        } else if ( peek_next("relay ") ) {
          expect("relay ");
          c.type(IceCandidate::relay);
        } else return false;

        if ( c.type() != IceCandidate::host ) {
          // Expect raddr / rport
          if ( !expect("raddr ") ) return false;

          if ( !parse_field(ip_address, sizeof(ip_address)) ) return false;
          c.raddr(boost::asio::ip::address::from_string(ip_address, ec));
          if ( ec ) return false;

          if ( !parse_decimal(port) ) return false;
          c.rport(port);
        }

        // There may be other attributes but we don't care for now

        return true;
      }

    private:
      bool parse_field(char *out, std::size_t n) {
        std::size_t i(0);
        for ( ; m_index < m_data.size() && i < n && m_data[m_index] != ' '; m_index++, i++ )
          out[i] = m_data[m_index];

        if ( i == 0 ) return false;

        out[std::min(i, n)] = '\0';

        if ( m_index < m_data.size() ) {
          if ( m_data[m_index] == ' ' ) {
            m_index++;
            return true;
          } else
            return false;
        } else
          return true;
      }

      template<typename N>
      bool parse_decimal(N &n) {
        int digits_read = 0;
        n = 0;

        for ( ; m_index < m_data.size() && isdigit(m_data[m_index]); m_index++, digits_read++ ) {
          int n_value = m_data[m_index] - '0';
          n *= 10;
          n += n_value;
        }

        if ( m_index < m_data.size() ) {
          if ( digits_read > 0 && m_data[m_index] == ' ' ) {
            m_index ++;
            return true;
          } else return false;
        } else
          return digits_read > 0;
      }

      inline bool peek_next(char c) {
        if ( m_index < m_data.size() )
          return m_data[m_index] == c;
        else
          return false;
      }

      bool peek_next(const char *s) {
        std::size_t index(m_index), i(0);
        for ( i = 0; index < m_data.size() && s[i] != '\0'; i++, index++)
          if ( m_data[index] != s[i] ) return false;

        return s[i] == '\0';
      }

      inline bool expect(char c) {
        if ( peek_next(c) ) {
          m_index ++;
          return true;
        } else
          return false;
      }

      bool expect(const char *s) {
        for ( std::size_t i = 0; s[i] != '\0'; i++ )
          if ( !expect(s[i]) )
            return false;

        return true;
      }

      bool m_valid;
      const std::string &m_data;
      std::size_t m_index;
    };

    // IceCandidate
    IceCandidate::IceCandidate()
      : m_component_id(0), m_transport(UDP),
        m_priority(0), m_type(host), m_rport(0) {
      m_foundation[0] = '\0';
      m_foundation[32] = '\0';
    }

    IceCandidate::IceCandidate(const IceCandidate &c)
      : m_component_id(c.m_component_id), m_transport(c.m_transport),
        m_priority(c.m_priority), m_type(c.m_type),
        m_addr(c.m_addr), m_raddr(c.m_raddr),
        m_port(c.m_port), m_rport(c.m_rport) {
      std::copy(c.m_foundation, c.m_foundation + sizeof(c.m_foundation), m_foundation);
    }

    void IceCandidate::swap(IceCandidate &c) {
      for ( unsigned int i = 0; i < sizeof(m_foundation) / sizeof(m_foundation[0]) ; ++i )
        std::swap(m_foundation[i], c.m_foundation[i]);

      std::swap(m_component_id, c.m_component_id);
      std::swap(m_transport, c.m_transport);
      std::swap(m_priority, c.m_priority);
      std::swap(m_type, c.m_type);
      std::swap(m_addr, c.m_addr);
      std::swap(m_raddr, c.m_raddr);
      std::swap(m_port, c.m_port);
      std::swap(m_rport, c.m_rport);
    }

    void IceCandidate::foundation(const char *foundation) {
      strncpy(m_foundation, foundation, 32);
    }

    bool IceCandidate::is_redundant(const IceCandidate &c) const {
      if ( c.m_type == m_type ) {
        switch ( m_type ) {
        case host:
          return c.m_addr == m_addr && c.m_port == m_port;
        default: return false;
        };
      } else
        return false;
    }

    std::string IceCandidate::as_sdp_string() const {
      std::stringstream s;
      s << "candidate:" << m_foundation << " " << ((int)m_component_id) << " ";

      switch ( m_transport ) {
      case UDP:
        s << "udp ";
        break;
      default:
        s << "unknown ";
        break;
      }

      s << m_priority << " " <<  m_addr << " " << m_port << " typ ";

      switch ( m_type ) {
      case host: s << "host "; break;
      case srflx: s << "srflx "; break;
      case prflx: s << "prflx "; break;
      case relay: s << "relay "; break;
      default:    s << "unknown "; break;
      }

      if ( m_type != host ) {
        s << "raddr " << m_raddr;
        s << " rport " << m_rport;
      }

      return s.str();
    }

    bool IceCandidate::from_string(const std::string &c) {
      IceCandidateParser p(c);
      IceCandidate tmp;
      bool success(p.parse(tmp));

      if ( success )
        swap(tmp);

      return success;
    }

    std::uint32_t IceCandidate::recommended_priority(std::uint16_t local_pref) const {
      std::uint32_t pt = (((std::uint32_t) local_pref) << 8) | component_id();

      std::uint8_t type_preference(0);
      switch ( type() ) {
      case host: type_preference = 126; break;
      case prflx: type_preference = 110; break;
      case srflx: type_preference = 100; break;
      default: case relay: type_preference = 0; break;
      }

      return pt | (((std::uint32_t) type_preference) << 24);
    }

    IceCandidate IceCandidate::base() const {
      if ( type() == host )
        return *this;
      else {
        auto r(*this);
        r.addr(raddr());
        r.port(rport());
        r.type(host);
        return r;
      }
    }

    // IceConnectivityListener
    // class IceConnectivityListener : public std::enable_shared_from_this<IceConnectivityListener> {
    // public:
    //   IceConnectivityListener(boost::asio::io_service &svc,
    //                           const boost::asio::ip::udp::endpoint &ep,
    //                           std::shared_ptr<IceCandidateCollector> c)
    //     : m_service(svc), m_socket(svc, ep.protocol()), m_collector(c) {
    //     m_socket.set_option(boost::asio::ip::udp::socket::reuse_address(true));
    //     m_socket.bind(ep);
    //   }
    //   ~IceConnectivityListener() {
    //     BOOST_LOG_TRIVIAL(debug) << "Destroying listener";
    //   }

    //   void async_serve() {
    //     auto shared(shared_from_this());
    //     auto stun_buffer(std::make_shared<StunMsgHdr>(shared->m_collector->gen(), StunMsgHdr::Binding));
    //     BOOST_LOG_TRIVIAL(debug) << "Waiting for connectivity check: " << m_socket.local_endpoint();

    //     m_socket.async_receive_from
    //       (stun_buffer->as_asio_recv_buffer(),
    //        m_remote,
    //        [shared, stun_buffer]
    //        ( boost::system::error_code ec, std::size_t bytes_recvd) {
    //         if ( ec ) {
    //           BOOST_LOG_TRIVIAL(error) << "ICE connectivity listener errors out: " << ec;
    //         } else {
    //           auto local(shared->m_socket.local_endpoint()), remote(shared->m_remote);

    //           if ( stun_buffer->validate() ) {
    //             shared->m_service.post([stun_buffer, shared, local, remote] () {
    //                 StunMsgHdr stun_response(stun_buffer->tx_id(), stun_buffer->response_type());
    //                 bool success(shared->m_collector->connectivity_check(remote, local, *stun_buffer,
    //                                                                      stun_response));
    //                 if ( success ) {
    //                   boost::unique_lock l(shared->m_socket_write_mutex);
    //                   shared->m_socket.send_to(stun_response.as_asio_send_buffer(), remote);
    //                 }
    //               });
    //           } else
    //             BOOST_LOG_TRIVIAL(debug) << "STUN msg invalid";

    //           shared->async_serve();
    //         }
    //       });
    //   }

    //   void cancel() {
    //     m_socket.cancel();
    //   }

    // private:
    //   boost::asio::io_service &m_service;
    //   boost::asio::ip::udp::socket m_socket;
    //   std::shared_ptr<IceCandidateCollector> m_collector;

    //   boost::mutex m_socket_write_mutex;

    //   boost::asio::ip::udp::endpoint m_remote;
    // };

    // IceCandidateCollector
    IceCandidateCollector::IceCandidateCollector(boost::asio::io_service &svc)
      : m_service(svc), m_cb_strand(m_service),
        m_host_resolver(svc) {
    }

    void IceCandidateCollector::add_ice_server(const uri::Uri &u) {
      if ( u.has_scheme("stun") ) {
        auto host(u.host());
        std::uint16_t port(3478);
        if ( u.has_port() )
          port = u.port();

        m_stun_servers.push_back(std::make_pair(host, port));
      }
    }

    void IceCandidateCollector::async_collect_candidates() {
      if ( m_stun_servers.empty() )
        on_ice_complete(boost::system::error_code(ENOENT, boost::system::system_category()));
      else {
        boost::unique_lock lock_completion(m_completion_mutex);
        m_stun_resolution_complete = 0;
        m_completion_error = boost::system::error_code();

        start_stun();
      }
    }

    void IceCandidateCollector::end_of_candidates() {
      boost::unique_lock l(m_completion_mutex);

      m_stun_resolution_complete --;

      if ( m_stun_resolution_complete == 0 ) {
        m_cb_strand.post(boost::bind(&IceCandidateCollector::on_ice_complete, base_shared_from_this(), m_completion_error));
      }
    }

    void IceCandidateCollector::flag_error(boost::system::error_code ec) {
      boost::unique_lock l(m_completion_mutex);
      m_completion_error = ec;
    }

    void IceCandidateCollector::collect_candidate(const IceCandidate &c) {
      m_cb_strand.post(boost::bind(&IceCandidateCollector::on_receive_ice_candidate, base_shared_from_this(), c));
    }

    void IceCandidateCollector::start_stun() {
      auto shared(base_shared_from_this());
      for ( const auto &stun_server : m_stun_servers ) {
        std::stringstream port;
        port << stun_server.second;
        m_host_resolver.async_resolve
          (boost::asio::ip::udp::resolver::query(stun_server.first, port.str()),
           [shared] ( boost::system::error_code ec, boost::asio::ip::udp::resolver::iterator entry) {
            if ( ec ) {
              shared->flag_error(ec);
            } else {
              boost::unique_lock l(shared->m_completion_mutex);
              for ( ; entry != boost::asio::ip::udp::resolver::iterator(); entry++ ) {
                // TODO we should actually trickle ICE candidates
                // over, rather than wait for all to be collected,
                // because sometimes, we will just never receive a
                // response
                shared->m_stun_resolution_complete ++;
                auto collector(std::make_shared<StunCollector>(shared->m_service, entry->endpoint(), shared));
                collector->async_collect();
              }
            }
          });
      }
    }

  }
}

