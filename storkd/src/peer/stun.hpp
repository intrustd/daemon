#ifndef __stork_peer_stun_HPP__
#define __stork_peer_stun_HPP__

#include <byteswap.h>
#include <boost/asio.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

namespace stork {
  namespace peer {
    constexpr std::uint32_t STUN_MAGIC_COOKIE = 0x2112a442;

    struct StunAttr {
    public:
      enum StunAttrType : std::uint16_t {
        MAPPED_ADDRESS = 0x0001,
        USERNAME = 0x0006,
        MESSAGE_INTEGRITY = 0x0008,
        ERROR_CODE = 0x0009,
        XOR_MAPPED_ADDRESS = 0x0020,
        PRIORITY = 0x0024,
        USE_CANDIDATE = 0x0025,
        FINGERPRINT = 0x8028,
        ICE_CONTROLLED = 0x8029,
        ICE_CONTROLLING = 0x802A,
        RESPONSE_ORIGIN = 0x802B,
        OTHER_ADDRESS = 0x802C,
      };
      inline StunAttr(StunAttrType type)
        : m_type(htons((std::uint16_t) type)),
          m_length(0) { }

      inline StunAttrType type() const { return (StunAttrType) ntohs(m_type); }
      inline std::uint16_t length() const { return ntohs(m_length); }

      inline void type(StunAttrType t) { m_type = htons((std::uint16_t) t); }
      inline void length(std::uint16_t l) { m_length = htons(l); }

      template<typename T>
      inline const T &data() const { return *((T*) (((std::uintptr_t) this) + 4)); }
      template<typename T>
      inline T &data() { return *((T *) (((std::uintptr_t) this) + 4)); }

    private:
      std::uint16_t m_type;
      std::uint16_t m_length;
    } __attribute__ ((packed));

    struct StunAttrIterator {
    public:
      inline StunAttrIterator(StunAttr *a) : m_attr(a) { }

      StunAttrIterator operator+(int i);
      StunAttrIterator &operator ++();
      inline StunAttrIterator &operator ++(int i) { return ++(*this); }

      inline StunAttr &operator *() { return *m_attr; }

      inline bool operator <(const StunAttrIterator &i) const { return m_attr < i.m_attr; }
      inline bool operator >(const StunAttrIterator &i) const { return m_attr > i.m_attr; }
      inline bool operator <=(const StunAttrIterator &i) const { return m_attr <= i.m_attr; }
      inline bool operator >=(const StunAttrIterator &i) const { return m_attr >= i.m_attr; }
      inline bool operator ==(const StunAttrIterator &i) const { return m_attr == i.m_attr; }
      inline bool operator !=(const StunAttrIterator &i) const { return m_attr != i.m_attr; }

      typedef StunAttr value_type;

    private:
      StunAttr *m_attr;
      friend struct StunMsgHdr;
    };

    struct StunTransactionId {
    public:
      template<typename Gen>
      StunTransactionId(Gen &gen) {
        boost::random::uniform_int_distribution<std::uint32_t> r;
        a = r(gen);
        b = r(gen);
        c = r(gen);
      }

      StunTransactionId(const StunTransactionId &s) =default;
      StunTransactionId() : a(0), b(0), c(0) { }

      inline bool operator ==(const StunTransactionId &x) const {
        return x.a == a && x.b == b && x.c == c;
      }

      std::uint32_t a, b, c;
    } __attribute__ ((packed));

    struct StunMsgHdr {
    public:
      enum StunMsgType : std::uint16_t {
        InvalidRequest = 0x0000,
        Binding = 0x0001,
        BindingResponse = 0x0101,
        BindingError = 0x0111
      };

      template<typename Gen>
      StunMsgHdr(Gen &gen, StunMsgType type)
        : m_type(htons((std::uint16_t) type)),
          m_len(0), m_magic_cookie(htonl(STUN_MAGIC_COOKIE)),
          m_tx_id(gen) {
      }
      StunMsgHdr(const StunTransactionId &id, StunMsgType type);
      inline StunMsgHdr() : m_type(InvalidRequest) { };

      inline StunMsgType type() const { return StunMsgType(ntohs(m_type)); }
      inline StunMsgType response_type() const { return StunMsgType(ntohs(m_type) | 0x0100); }
      inline const StunTransactionId &tx_id() const { return m_tx_id; }

      bool validate(const StunTransactionId &id) const;
      bool validate() const;

      boost::asio::const_buffer as_asio_send_buffer() const;

      boost::asio::mutable_buffer as_asio_recv_buffer();

      StunAttrIterator begin() const;
      StunAttrIterator end() const;

      std::uint32_t crc_fingerprint() const;

      // hash_out must be 20 bytes in length
      bool message_integrity(const char *key, std::size_t key_len, char *hash_out) const;

      template<typename Attr>
      Attr &add_attr(const Attr &from) {
        std::uint16_t new_len = length() + 4 * ((4 + from.size() + 3) / 4);
        if ( new_len  > sizeof(m_attributes) )
          throw std::out_of_range("No more space for attribute");

        StunAttr *a((StunAttr *) (m_attributes + length()));
        m_len = htons(new_len);
        a->type(Attr::attr_type);
        a->length(from.size());

        new (&(a->data<Attr>())) Attr(from);

        return a->data<Attr>();
      }

      template<typename Attr, typename ...Args>
      Attr &add_attr(Args... args) {
        return add_attr<Attr>(Attr(args...));
      }

    private:
      std::uint16_t length() const;

      std::uint16_t m_type;
      std::uint16_t m_len;
      std::uint32_t m_magic_cookie;
      StunTransactionId m_tx_id;
      char m_attributes[556]; // Hard limit of 576 for STUN messages, as far as we're concerned
    } __attribute__ ((packed));

    struct MappedAddressData {
    public:
      MappedAddressData(const boost::asio::ip::udp::endpoint &addr);

      static constexpr StunAttr::StunAttrType attr_type = StunAttr::MAPPED_ADDRESS;

      bool is_ipv4() const;
      bool is_ipv6() const;
      std::uint16_t in_addr_type() const;

      boost::asio::ip::address ip_address(bool is_xor, const StunTransactionId &tx_id) const;

      std::uint16_t port(bool is_xor) const;

      std::uint16_t size() const;

    protected:
      void reset(const boost::asio::ip::udp::endpoint &addr);

      std::uint16_t m_in_addr_type;
      std::uint16_t m_port;
      union {
        struct in_addr m_ipv4_addr;
        struct in6_addr m_ipv6_addr;
      };
    } __attribute__ ((packed));

    struct XorMappedAddressData : public MappedAddressData {
      XorMappedAddressData(const boost::asio::ip::udp::endpoint &a,
                           const StunTransactionId &tx_id);
      static constexpr StunAttr::StunAttrType attr_type = StunAttr::XOR_MAPPED_ADDRESS;
    } __attribute__ ((packed));

    struct MessageIntegrityData {
      static constexpr StunAttr::StunAttrType attr_type = StunAttr::MESSAGE_INTEGRITY;
      inline std::uint16_t size() const { return sizeof(*this); }

      bool verify_message(const StunMsgHdr &req,
                          const char *pwd, std::size_t pwd_len) const;
      // TODO write message integrity

      char hmac_fingerprint[20];
    } __attribute__ ((packed));

    struct FingerprintData {
    public:
      static constexpr StunAttr::StunAttrType attr_type = StunAttr::FINGERPRINT;
      inline void fingerprint(std::uint32_t i) { m_fingerprint = htonl(i); }
      inline std::uint32_t fingerprint() const { return ntohl(m_fingerprint); }

      inline std::uint16_t size() const { return sizeof(*this); }
    private:
      std::uint32_t m_fingerprint;
    } __attribute__ ((packed));

    struct ErrorCodeData {
    public:
      ErrorCodeData(std::uint16_t code, const char *reason_phrase);

      static constexpr StunAttr::StunAttrType attr_type = StunAttr::ERROR_CODE;

      std::uint16_t code() const;
      std::string status_string(std::uint16_t l) const;

      inline std::uint16_t size() const { return sizeof(m_code) + strnlen(m_reason_phrase, sizeof(m_reason_phrase)); }
    private:
      std::uint32_t m_code;
      char m_reason_phrase[64];
    };

    struct UsernameData {
    public:
      UsernameData(const char *remote_user, const char *local_user) {
        std::copy(remote_user, remote_user + 4, m_username);
        m_username[4] = ':';
        std::copy(local_user, local_user + 4, m_username + 5);
      }

      inline std::uint16_t size() const { return sizeof(*this); }
      static constexpr StunAttr::StunAttrType attr_type = StunAttr::USERNAME;

      inline std::string remote_user() const { return std::string(m_username, m_username + 4); }
      inline std::string local_user() const { return std::string(m_username + 5, m_username + 9); }

      inline bool is_valid(const char *remote_user, const char *local_user) const {
        return m_username[4] == ':' && std::equal(m_username, m_username + 4, remote_user)
          && std::equal(m_username + 5, m_username + 9, local_user);
      }

    public:
      char m_username[9];
    };

    struct PriorityData {
    public:
      PriorityData(std::uint32_t prio_data)
        : m_prio(htonl(prio_data)) {
      }

      inline std::uint32_t prio() const { return ntohl(m_prio); }

      inline std::uint16_t size() const { return sizeof(*this); }
      static constexpr StunAttr::StunAttrType attr_type = StunAttr::PRIORITY;

    private:
      std::uint32_t m_prio;
    };

    struct IceControlled {
      static constexpr StunAttr::StunAttrType attr_type = StunAttr::ICE_CONTROLLED;

      IceControlled(std::uint64_t tie_breaker)
        : m_tie_breaker(bswap_64(tie_breaker)) {
      }

      inline std::uint16_t size() const { return 8; }

    private:
      std::uint64_t m_tie_breaker;
    };

    // StunCollector
    class IceCandidateCollector;
    class StunCollector : public std::enable_shared_from_this<StunCollector> {
    public:
      StunCollector(boost::asio::io_service &s,
                    const boost::asio::ip::udp::endpoint &server,
                    std::shared_ptr<IceCandidateCollector> c,
                    std::size_t max_requests = 7);
      ~StunCollector();

      void async_collect();
      void cancel();

    private:
      void start_read();
      void retransmit(boost::system::error_code ec);

      void message_sent(boost::system::error_code ec, bool first_time);
      void message_received(boost::system::error_code ec);

      boost::asio::io_service &m_service;
      boost::asio::ip::udp::endpoint m_server, m_real_server_addr;
      std::shared_ptr<IceCandidateCollector> m_collector;

      boost::asio::ip::udp::socket m_socket;
      StunMsgHdr m_stun_msg, m_stun_response;
      StunTransactionId m_req_id;

      std::size_t m_max_requests, m_requests_left;

      boost::posix_time::time_duration m_rto;
      boost::asio::deadline_timer m_rto_timer;
    };
  }
}

namespace std {
  template<>
  struct iterator_traits<stork::peer::StunAttrIterator> {
    typedef int difference_type;
    typedef std::forward_iterator_tag iterator_category;
  };
}

#endif
