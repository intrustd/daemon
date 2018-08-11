#include <boost/log/trivial.hpp>
#include <boost/crc.hpp>
#include <boost/bind.hpp>
#include <openssl/hmac.h>

#include "stun.hpp"
#include "ice.hpp"

namespace stork {
  namespace peer {
    // StunAttrIterator
    StunAttrIterator &StunAttrIterator::operator++()  {
      std::uintptr_t attr_ptr((std::uintptr_t) m_attr);
      attr_ptr += 4 + 4 * ((m_attr->length() + 3) / 4);
      m_attr = (StunAttr *) attr_ptr;
      return *this;
    }

    StunAttrIterator StunAttrIterator::operator+(int i) {
      auto n(*this);
      std::advance(n, i);
      return n;
    }

    // StunMsgHdr
    StunMsgHdr::StunMsgHdr(const StunTransactionId &id, StunMsgType type)
      : m_type(htons((std::uint16_t) type)),
        m_len(0), m_magic_cookie(htonl(STUN_MAGIC_COOKIE)),
        m_tx_id(id) {
    }

    bool StunMsgHdr::validate(const StunTransactionId &id) const {
      return ntohl(m_magic_cookie) == STUN_MAGIC_COOKIE &&
        (type() & 0xC0) == 0 &&
        m_tx_id == id &&
        ntohs(m_len) < sizeof(m_attributes);
    }

    bool StunMsgHdr::validate() const {
      return validate(m_tx_id);
    }


    boost::asio::const_buffer StunMsgHdr::as_asio_send_buffer() const {
      return boost::asio::buffer((char *) this, 20 + length());
    }

    boost::asio::mutable_buffer StunMsgHdr::as_asio_recv_buffer() {
      return boost::asio::buffer((char *) this, sizeof(*this));
    }

    StunAttrIterator StunMsgHdr::begin() const {
      return StunAttrIterator((StunAttr *) m_attributes);
    }

    StunAttrIterator StunMsgHdr::end() const {
      return StunAttrIterator((StunAttr *) (m_attributes + length()));
    }

    std::uint16_t StunMsgHdr::length() const {
      return 4 * ((ntohs(m_len) + 3) / 4);
    }

    std::uint32_t StunMsgHdr::crc_fingerprint() const {
      boost::crc_32_type crc;
      // Subtract 8 to ignore fingerprint attribute itself
      crc.process_block((char *) this, (char *)m_attributes + (std::max((std::uint16_t) 8, length()) - 8));
      return crc.checksum() ^ 0x5354554e;
    }

    bool StunMsgHdr::message_integrity(const char *key, std::size_t key_len,
                                       char *hash_out) const {
      const char *end(NULL), *length_end(NULL);
      for ( StunAttr &a : *this ) {
        if ( a.type() == StunAttr::MESSAGE_INTEGRITY ) {
          end = (const char *) &a;
          length_end = &(a.data<char>()) + sizeof(MessageIntegrityData);
          break;
        }
      }

      if ( !end || !length_end ) return false;
      std::uint16_t virtual_length(htons(length_end - m_attributes));

      std::shared_ptr<HMAC_CTX> ctx(HMAC_CTX_new(), HMAC_CTX_free);
      if ( !ctx )
        throw std::bad_alloc(); // TODO what to do here?

      if ( !HMAC_Init_ex(ctx.get(), key, key_len, EVP_sha1(), NULL) ) return false;

      if ( !HMAC_Update(ctx.get(), (unsigned char*) &m_type, sizeof(m_type)) ) return false;
      if ( !HMAC_Update(ctx.get(), (unsigned char*) &virtual_length, sizeof(virtual_length)) ) return false;
      if ( !HMAC_Update(ctx.get(), (unsigned char*) &m_magic_cookie, end - ((char *)&m_magic_cookie)) ) return false;

      unsigned int len = 20;
      if ( !HMAC_Final(ctx.get(), (unsigned char *) hash_out, &len) ) return false;
      if ( len != 20 ) return false;

      return true;
    }

    // MappedAddressData
    MappedAddressData::MappedAddressData(const boost::asio::ip::udp::endpoint &addr) {
      reset(addr);
    }

    bool MappedAddressData::is_ipv4() const {
      return in_addr_type() == 0x01;
    }

    bool MappedAddressData::is_ipv6() const {
      return in_addr_type() == 0x02;
    }

    std::uint16_t MappedAddressData::in_addr_type() const {
      return ntohs(m_in_addr_type);
    }

    std::uint16_t MappedAddressData::size() const {
      if ( is_ipv4() ) return 8;
      else return 20;
    }

    void MappedAddressData::reset(const boost::asio::ip::udp::endpoint &addr) {
      if ( addr.address().is_v6() ) {
        m_in_addr_type = htons(0x2);
        std::array<std::uint8_t, 16> addr_bytes(addr.address().to_v6().to_bytes());
        std::copy(addr_bytes.begin(), addr_bytes.end(), m_ipv6_addr.s6_addr);
      } else if ( addr.address().is_v4() ) {
        m_in_addr_type = htons(0x1);
        std::array<std::uint8_t, 4> addr_bytes(addr.address().to_v4().to_bytes());
        std::copy(addr_bytes.begin(), addr_bytes.end(), (std::uint8_t *)&m_ipv4_addr.s_addr);
      }

      m_port = htons(addr.port());
    }

    boost::asio::ip::address MappedAddressData::ip_address(bool is_xor, const StunTransactionId &tx_id) const  {
      if ( is_ipv4() ) {
        auto r(ntohl(m_ipv4_addr.s_addr));
        if ( is_xor )
          r ^= STUN_MAGIC_COOKIE;
        return boost::asio::ip::address_v4(r);
      } else if ( is_ipv6() ) {
        std::array<std::uint8_t, 16> addr;
        std::copy(m_ipv6_addr.s6_addr, m_ipv6_addr.s6_addr + 16, addr.begin());

        if ( is_xor ) {
          // MAGIC cookie
#define BYTE0(a) ((a >> 24) & 0xFF)
#define BYTE1(a) ((a >> 16) & 0xFF)
#define BYTE2(a) ((a >> 8)  & 0xFF)
#define BYTE3(a) (a & 0xFF)
          addr[0] ^= 0x21; addr[1] ^= 0x12;
          addr[2] ^= 0xa4; addr[3] ^= 0x42;
          addr[4] ^= BYTE3(tx_id.a); addr[5] ^= BYTE2(tx_id.a);
          addr[6] ^= BYTE1(tx_id.a); addr[7] ^= BYTE0(tx_id.a);
          addr[8] ^= BYTE3(tx_id.b); addr[9] ^= BYTE2(tx_id.b);
          addr[10] ^= BYTE1(tx_id.b); addr[11] ^= BYTE0(tx_id.b);
          addr[12] ^= BYTE3(tx_id.c); addr[13] ^= BYTE2(tx_id.c);
          addr[14] ^= BYTE1(tx_id.c); addr[15] ^= BYTE0(tx_id.c);
#undef BYTE0
#undef BYTE1
#undef BYTE2
#undef BYTE3
        }

        return boost::asio::ip::address_v6(addr, 0);
      } else
        return boost::asio::ip::address();
    }

    std::uint16_t MappedAddressData::port(bool is_xor) const {
      auto r = ntohs(m_port);
      if ( is_xor ) {
        r ^= (STUN_MAGIC_COOKIE >> 16) & 0xFFFF;
      }
      return r;
    }

    XorMappedAddressData::XorMappedAddressData(const boost::asio::ip::udp::endpoint &a,
                                               const StunTransactionId &id)
      : MappedAddressData(a) {

      boost::asio::ip::udp::endpoint fixed(ip_address(true, id), port(true));
      reset(fixed);
    }

    bool MessageIntegrityData::verify_message(const StunMsgHdr &req,
                                              const char *pwd, std::size_t pwd_len) const {
      char actual_hmac[20];
      if ( !req.message_integrity(pwd, pwd_len, actual_hmac) ) return false;

      return std::equal(actual_hmac, actual_hmac + sizeof(actual_hmac),
                        hmac_fingerprint);
    }

    ErrorCodeData::ErrorCodeData(std::uint16_t err_code, const char *status_string)
      : m_code(htonl((((err_code / 100) & 0xF) << 8) +
                     (err_code % 100))) {
      std::size_t string_length(std::min(sizeof(m_reason_phrase) - 1, strlen(status_string)));
      *std::copy(status_string, status_string + string_length, m_reason_phrase) = '\0';
    }

    std::uint16_t ErrorCodeData::code() const {
      // The most esoteric encoding known to man kind...
      std::uint32_t code(ntohl(m_code));
      std::uint16_t err(code & 0xFF);
      err = std::min<std::uint16_t>(err, 99);

      std::uint16_t cls((code >> 8) & 0xF);
      cls = std::max<std::uint16_t>(std::min<std::uint16_t>(cls, 6), 3);

      return cls * 100 + err;
    }

    std::string ErrorCodeData::status_string(std::uint16_t l) const {
      return std::string(m_reason_phrase, m_reason_phrase + l);
    }

    // StunCollector
    StunCollector::StunCollector(boost::asio::io_service &s,
                                 const boost::asio::ip::udp::endpoint &server,
                                 std::shared_ptr<IceCandidateCollector> c,
                                 std::size_t max_requests)
      : m_service(s), m_server(server), m_collector(c), m_socket(s, server.protocol()),
        m_stun_msg(m_collector->gen(), StunMsgHdr::Binding),
        m_stun_response(StunTransactionId(), StunMsgHdr::BindingResponse),
        m_req_id(m_stun_msg.tx_id()),
        m_max_requests(max_requests), m_requests_left(max_requests),
        m_rto(boost::posix_time::seconds(3)), // TODO estimate
        m_rto_timer(m_service)
    {
      m_socket.set_option(boost::asio::ip::udp::socket::reuse_address(true));
    }

    StunCollector::~StunCollector() {
      cancel();
      m_service.post(boost::bind(&IceCandidateCollector::end_of_candidates, m_collector));
    }

    void StunCollector::async_collect() {
      auto shared(shared_from_this());

      boost::system::error_code ec;
      m_socket.connect(m_server, ec); // Connecting now ensures we get a bound host address

      if ( ec )
        BOOST_LOG_TRIVIAL(error) << "Could not connect: " << ec;
      else {
        m_socket.async_send_to
          (m_stun_msg.as_asio_send_buffer(), m_server,
           boost::bind(&StunCollector::message_sent, shared, boost::placeholders::_1, true));
      }
    }

    void StunCollector::cancel() {
      m_socket.cancel();
      m_rto_timer.cancel();
    }

    void StunCollector::message_sent(boost::system::error_code ec, bool first_time) {
      if ( ec ) {
        BOOST_LOG_TRIVIAL(error) << "Error contacting stun service: " << ec;
      } else if ( first_time ) {
        auto host_ep(m_socket.local_endpoint());

        IceCandidate c;
        c.transport(IceCandidate::UDP);
        c.addr(host_ep.address());
        c.port(host_ep.port());
        c.type(IceCandidate::host);

        m_collector->collect_candidate(c);

        start_read();
      }

      m_requests_left--;

      if ( m_requests_left > 0 ) {
        m_rto_timer.expires_from_now(m_rto);
        m_rto_timer.async_wait(boost::bind(&StunCollector::retransmit, shared_from_this(), boost::placeholders::_1));
      }
    }

    void StunCollector::start_read() {
      m_socket.async_receive_from
        (m_stun_response.as_asio_recv_buffer(), m_real_server_addr,
         boost::bind(&StunCollector::message_received, shared_from_this(), boost::placeholders::_1));
    }

    void StunCollector::retransmit(boost::system::error_code ec) {
      if ( !ec ) { // Only perform when there is no error (error is usually from cancellation)
        m_rto *= 2;
        m_socket.async_send_to(m_stun_msg.as_asio_send_buffer(), m_server,
                               boost::bind(&StunCollector::message_sent, shared_from_this(), boost::placeholders::_1, true));
      }
    }

    void StunCollector::message_received(boost::system::error_code ec) {
      if ( ec ) {
        BOOST_LOG_TRIVIAL(debug) << "Error receiving stun response: " << ec;
        // TODO finish with error
        goto error;
      } else if ( m_stun_response.validate(m_req_id) ) {

        if ( m_stun_response.type() == StunMsgHdr::BindingResponse ) {
          auto host_ep(m_socket.local_endpoint());
          // Collect the address here and send it to the collector
          IceCandidate srflx;
          srflx.transport(IceCandidate::UDP);
          srflx.type(IceCandidate::srflx);
          srflx.raddr(host_ep.address());
          srflx.rport(host_ep.port());

          bool found_address = false, addresses_same = true;

          for ( StunAttr &attr : m_stun_response ) {
            switch ( attr.type() ) {
            case StunAttr::XOR_MAPPED_ADDRESS:
            case StunAttr::MAPPED_ADDRESS: {
              bool is_xor(attr.type() == StunAttr::XOR_MAPPED_ADDRESS);
              auto mapped_address(attr.data<MappedAddressData>());
              if ( mapped_address.is_ipv4() || mapped_address.is_ipv6() ) {
                if ( !found_address ) {
                  found_address = true;
                  srflx.addr(mapped_address.ip_address(is_xor, m_req_id));
                  srflx.port(mapped_address.port(is_xor));
                } else {
                  addresses_same = addresses_same &&
                    srflx.addr() == mapped_address.ip_address(is_xor, m_req_id) &&
                    srflx.port() == mapped_address.port(is_xor);
                }
              }
              break;
            }
            default: break;
            }
          }

          if ( !found_address ) {
            BOOST_LOG_TRIVIAL(error) << "STUN response did not contain any address";
            goto restart;
          } else if ( !addresses_same ) {
            BOOST_LOG_TRIVIAL(error) << "STUN response address mismatch. Got " << srflx.addr() << " " << srflx.port();
            goto restart;
          } else {
            m_collector->collect_candidate(srflx);
            cancel();
          }
        } else if ( m_stun_response.type() == StunMsgHdr::BindingError ) {
          BOOST_LOG_TRIVIAL(error) << "STUN response error";
          ErrorCodeData *error_code(NULL);
          std::string status_string;
          for ( StunAttr &attr : m_stun_response ) {
            if ( attr.type() == StunAttr::ERROR_CODE ) {
              error_code = &(attr.data<ErrorCodeData>());
              status_string = error_code->status_string(attr.length());
              break;
            }
          }

          if ( !error_code ) {
            BOOST_LOG_TRIVIAL(error) << "Error response with no ERROR-CODE attribute";
            goto restart; // Invalid error
          } else
            BOOST_LOG_TRIVIAL(error) << "STUN binding response error: " << error_code->code() << ": " << status_string;
        } else {
          BOOST_LOG_TRIVIAL(error) << "Invalid response to binding request";
          goto error;
        }
      } else goto restart;

      return;

    restart:
      start_read();
      return;

    error:
      // TODO actually error out
      cancel();
    }
  }
}
