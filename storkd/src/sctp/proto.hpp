#ifndef __stork_sctp_proto_HPP__
#define __stork_sctp_proto_HPP__

#include <openssl/sha.h>
#include <boost/asio.hpp>
#include <arpa/inet.h>
#include <byteswap.h>
#include <iterator>
#include <vector>

namespace stork {
  namespace sctp {
    // Data structures corresponding to https://tools.ietf.org/html/rfc4960

    typedef std::uint16_t SctpStreamId;
    typedef std::uint16_t SctpStreamSequenceNumber;

    template<typename HdrPtr, typename ChunkType>
    class ChunkIterator {
    public:
      inline ChunkIterator(HdrPtr &ptr, std::uint8_t *buf)
        : m_header(ptr), m_pos(buf) {

      }

      bool valid() const {
        return m_pos <= m_header.end().m_pos;
      }

      inline ChunkIterator<HdrPtr, ChunkType> &operator ++() { m_pos = next_pos(); return *this; }
      inline ChunkIterator<HdrPtr, ChunkType> &operator ++(int i) { m_pos = next_pos(); return *this; }

      ChunkType &operator *() const { return *(ChunkType *)m_pos; }
      ChunkType *operator->() const { return &(*(*this)); }

      inline bool operator ==(const ChunkIterator<HdrPtr, ChunkType> &i) const {
        if ( i.valid() && valid() ) {
          return m_pos == i.m_pos;
        } else
          return !valid() && !i.valid();
      }
      inline bool operator !=(const ChunkIterator<HdrPtr, ChunkType> &i) const {
        return !(*this == i);
      }

    private:
      inline std::uint8_t *next_pos() const {
        return m_pos + (*this)->padded_size();
      }

      HdrPtr &m_header;
      std::uint8_t *m_pos;
    };

    template<typename Hdr, typename Chunk>
    class HeaderPtr {
    public:
      using value_type = Hdr;
      using chunk_type = Chunk;

      inline HeaderPtr(std::vector<std::uint8_t> &raw_data)
        : m_buffer(raw_data.data()), m_buffer_size(raw_data.size()) {
      }

      inline HeaderPtr(std::uint8_t *buf, std::size_t sz)
        : m_buffer(buf), m_buffer_size(sz) {
      }

      inline Hdr *operator->() const { return get(); }
      inline Hdr &operator*() const { return *get(); }
      inline Hdr *get() const { return (Hdr *) m_buffer; }

      using iterator = ChunkIterator< HeaderPtr<Hdr, Chunk>, Chunk >;
      inline iterator begin() {
        return iterator(*this, m_buffer + sizeof(Hdr));
      }
      inline iterator end() {
        return iterator(*this, m_buffer + m_buffer_size);
      }

    protected:
      inline std::uint8_t *buffer() const { return m_buffer; }
      inline std::size_t buffer_size() const { return m_buffer_size; }

    private:
      std::uint8_t *m_buffer;
      std::size_t m_buffer_size;
    };

    class SctpHeader {
    public:
      inline SctpHeader(std::uint16_t source, std::uint16_t destination)
        : m_source_port(htons(source)), m_destination_port(htons(destination)) {
      }
      ~SctpHeader();

      inline std::uint16_t source_port() const { return ntohs(m_source_port); }
      inline void source_port(std::uint16_t p) { m_source_port = htons(p); }
      inline std::uint16_t destination_port() const { return ntohs(m_destination_port); }
      inline void destination_port(std::uint16_t p) { m_destination_port = htons(p); }

      inline std::uint32_t actual_checksum() const { return m_checksum; }
      inline void checksum(std::uint32_t cs) { m_checksum = cs; }

      inline std::uint32_t verification_tag() const { return ntohl(m_verification); }
      inline void verification_tag(std::uint32_t v) { m_verification = htonl(v); }
    private:
      std::uint16_t m_source_port, m_destination_port;
      std::uint32_t m_verification;
      std::uint32_t m_checksum;
    } __attribute__ ((packed));

    enum SctpChunkType : std::uint8_t {
      DATA = 0x00,
      INIT = 0x01,
      INIT_ACK = 0x02,
      SACK = 0x03,
      HEARTBEAT = 0x04,
      HEARTBEAT_ACK = 0x05,
      ABORT = 0x06,
      SHUTDOWN = 0x07,
      SHUTDOWN_ACK = 0x08,
      ERROR = 0x09,
      COOKIE_ECHO = 0x0A,
      COOKIE_ACK = 0x0B,
      ECNE = 0x0C, // Reserved
      SHUTDOWN_COMPLETE = 0x0E
    };

    class InitChunk;
    class CookieEcho;
    class DataChunk;
    class SctpChunkHeader;

    class ISctpChunkHandler {
    public:
      virtual void init_chunk(InitChunk &chunk) =0;
      virtual void cookie_echo(CookieEcho &echo) =0;
      virtual void data_chunk(DataChunk &chunk) =0;
      virtual void unknown_chunk_type(SctpChunkHeader &chunk) =0;
    };

    class SctpChunkPrinter : public ISctpChunkHandler {
    public:
      virtual void init_chunk(InitChunk &chunk);
      virtual void unknown_chunk_type(SctpChunkHeader &chunk);
    };

    class SctpChunkHeader {
    public:
      inline SctpChunkHeader(SctpChunkType chunk_type, std::uint8_t chunk_flags,
                             std::uint16_t chunk_length)
        : m_chunk_type((std::uint8_t) chunk_type), m_chunk_flags(chunk_flags),
          m_chunk_length(htons(chunk_length)) {
      }

      inline std::uint16_t padded_size() const { return 4 * ((raw_size() + 3) / 4); }
      inline std::uint16_t raw_size() const { return ntohs(m_chunk_length); }
      inline void resize(std::uint16_t new_sz) {
        m_chunk_length = htons(new_sz);
      }

      inline std::uint8_t flags() const { return m_chunk_flags; }

      inline SctpChunkType chunk_type() const { return (SctpChunkType) m_chunk_type; }

      void dispatch(ISctpChunkHandler &handle);

    private:
      template<typename T>
      T &data() {
        return *((T *) this);
      }

      std::uint8_t m_chunk_type;
      std::uint8_t m_chunk_flags;
      std::uint16_t m_chunk_length;
    } __attribute__((packed));

    struct ActionOnUnrecognized {
    public:
      inline ActionOnUnrecognized(std::uint8_t a) : action(a) { };

      inline bool stop_processing() const { return (action & 0x2) == 0; }
      inline bool skip_processing() const { return (action & 0x2) == 0x2; }

      inline bool send_report() const { return (action & 0x1) == 0x1; }
    private:
      std::uint8_t action;
    };

    enum ParameterType : std::uint16_t {
      IPv4_ADDRESS = 5,
      IPv6_ADDRESS = 6,
      STATE_COOKIE = 7,
      UNRECOGNIZED_PARAMETER = 8,
      COOKIE_PRESERVATIVE = 9,
      HOST_NAME_ADDRESS = 11,
    };

    class Parameter {
    public:
      inline std::uint16_t raw_size() const { return ntohs(m_length); }
      inline std::uint16_t padded_size() const { return 4 * ((raw_size() + 3) / 4); }

      // Per section 3.2.1
      inline ParameterType type() const { return ParameterType (ntohs(m_type) & 0x3F); }
      inline ActionOnUnrecognized if_unrecognized() const { return ActionOnUnrecognized((ntohs(m_type) >> 14) & 0x3); }

    protected:
      Parameter(ParameterType ty, std::uint16_t sz)
        : m_type(htons((std::uint16_t) ty)),
          m_length(htons(sz)) {
      }

    private:
      std::uint16_t m_type;
      std::uint16_t m_length;
    };

    class InitChunk {
    public:
      inline SctpChunkHeader &header() { return m_header; }

      inline std::uint32_t initiate_tag() const { return ntohl(m_initiate_tag); }
      inline std::uint32_t a_rwnd() const { return ntohl(m_a_rwnd); }
      inline std::uint16_t num_outbound() const { return ntohs(m_num_outbound);}
      inline std::uint16_t num_inbound() const { return ntohs(m_num_inbound); }
      inline std::uint32_t initial_tsn() const { return ntohl(m_initial_tsn); }

      using iterator = ChunkIterator<InitChunk, Parameter>;
      inline iterator begin() { return iterator(*this, m_data); }
      inline iterator end() { return iterator(*this, ((std::uint8_t*)this) + header().padded_size()); }

    protected:
      inline InitChunk(bool is_ack,
                       std::uint32_t tag, std::uint32_t a_rwnd,
                       std::uint16_t ob_streams,
                       std::uint16_t ib_streams,
                       std::uint32_t initial_tsn)
        : m_header(is_ack ? INIT_ACK : INIT, 0, sizeof(*this)),
          m_initiate_tag(htonl(tag)), m_a_rwnd(htonl(a_rwnd)),
          m_num_outbound(htons(ob_streams)), m_num_inbound(htons(ib_streams)),
          m_initial_tsn(htonl(initial_tsn)) {
      }

      SctpChunkHeader m_header;
      std::uint32_t m_initiate_tag;
      std::uint32_t m_a_rwnd;
      std::uint16_t m_num_outbound, m_num_inbound;
      std::uint32_t m_initial_tsn;
      std::uint8_t m_data[];
    } __attribute__((packed));

    class InitAckChunk : public InitChunk {
    public:
      inline InitAckChunk (std::uint32_t tag,
                           std::uint32_t rwnd,
                           std::uint16_t ob_streams,
                           std::uint16_t ib_streams,
                           std::uint32_t initial_tsn)
        : InitChunk(true, tag, rwnd, ob_streams, ib_streams, initial_tsn) {
      }

    } __attribute__((packed));

    class CookieAckChunk {
    public:
      inline CookieAckChunk()
        : m_header(COOKIE_ACK, 0, sizeof(*this)) {
      }

      inline SctpChunkHeader &header() { return m_header; }

    private:
      SctpChunkHeader m_header;
    } __attribute__((packed));

    struct StateCookieData;
    class CookieEcho {
    public:
      inline SctpChunkHeader &header() { return m_header; }

      inline StateCookieData &cookie() { return *((StateCookieData *) m_data); }

      inline const std::uint8_t *data() const { return m_data; }

    private:
      SctpChunkHeader m_header;
      std::uint8_t m_data[];
    } __attribute__((packed));

    class GapAck {
    public:
      inline GapAck(std::uint32_t last_tsn, const std::pair<std::uint32_t, std::uint32_t> &recvd)
        : m_gap_start(htons(recvd.first - last_tsn)),
          m_gap_length(htons(recvd.second - recvd.first)) {
      }

    private:
      std::uint16_t m_gap_start, m_gap_length;
    };

    class SelectiveAck {
    public:
      template<typename Gaps, typename Dups>
      SelectiveAck(std::uint32_t cum_tsn, std::uint32_t rwnd,
                   const Gaps &gaps, const Dups &dups)
        : m_header(SACK, 0, size(cum_tsn, rwnd, gaps, dups)),
          m_cum_tsn(htonl(cum_tsn)), m_rwnd(htonl(rwnd)),
          m_num_gap_acks(htons(gaps.size())), m_num_dup_tsns(htons(dups.size()))
      {
        GapAck *gap_ack((GapAck *) m_data);
        for ( auto &gap : gaps ) {
          new (gap_ack) GapAck(cum_tsn, gap);
          gap_ack ++;
        }

        std::copy(dups.begin(), dups.end(), (std::uint32_t *) gap_ack);
      }

      template<typename Gaps, typename Dups>
      static std::size_t size(std::uint32_t cum_tsn, std::uint32_t rwnd,
                              const Gaps &gaps, const Dups &dups) {
        return sizeof(SelectiveAck) + sizeof(GapAck) * gaps.size() + sizeof(std::uint32_t) * dups.size();
      }

      inline SctpChunkHeader &header() { return m_header; }

      inline std::uint32_t cum_tsn() const { return ntohl(m_cum_tsn); }

      inline std::uint32_t rwnd() const { return ntohl(m_rwnd); }

    private:
      SctpChunkHeader m_header;
      std::uint32_t m_cum_tsn;
      std::uint32_t m_rwnd;
      std::uint16_t m_num_gap_acks, m_num_dup_tsns;
      std::uint8_t m_data[];
    } __attribute__((packed));

    class DataChunk {
    public:
      inline SctpChunkHeader &header() { return m_header; }
      inline const SctpChunkHeader &header() const { return m_header; }

      inline std::uint32_t tsn() const { return ntohl(m_tsn); }

      inline SctpStreamId stream_id() const { return ntohs(m_stream_id); }

      inline SctpStreamSequenceNumber ssn() const { return ntohs(m_stream_sequence); }

      inline std::uint32_t payload_protocol() const { return ntohl(m_payload_protocol); }

      inline std::size_t user_data_size() const {
        if ( header().raw_size() > sizeof(*this) )
          return header().raw_size() - sizeof(*this);
        else return 0;
      }

      template<typename T>
      inline const T *user_data() const { return (const T*) m_user_data; }

      template<typename T>
      inline T *user_data() { return (T *) m_user_data; }

      inline const std::uint8_t *begin() const { return user_data<std::uint8_t>(); }
      inline const std::uint8_t *end() const { return begin() + user_data_size(); }

      struct Flags {
        static const std::uint8_t SACK_IMMEDIATELY = 0x08;
        static const std::uint8_t UNORDERED = 0x04;
        static const std::uint8_t BEGINNING = 0x02;
        static const std::uint8_t ENDING = 0x01;
      };

      inline bool sack_immediately() const { return (header().flags() & Flags::SACK_IMMEDIATELY) == Flags::SACK_IMMEDIATELY; }
      inline bool unordered() const { return (header().flags() & Flags::UNORDERED) == Flags::UNORDERED; }
      inline bool is_beginning() const { return (header().flags() & Flags::BEGINNING) == Flags::BEGINNING; }
      inline bool is_end() const { return (header().flags() & Flags::ENDING) == Flags::ENDING; }
      inline bool fragmented() const { return !is_beginning() || !is_end(); }

    private:
      SctpChunkHeader m_header;
      std::uint32_t m_tsn;
      SctpStreamId m_stream_id;
      SctpStreamSequenceNumber m_stream_sequence;
      std::uint32_t m_payload_protocol;
      char m_user_data[];
    } __attribute__((packed));

    class SctpHeaderPtr;
    struct StateCookieData {
    public:
      void calculate_mac(const std::uint8_t *key, std::size_t key_len, std::uint8_t *out);
      bool verify_mac(const std::uint8_t *key, std::size_t key_len);

      inline std::uint8_t *mac() { return m_mac; }
      inline const std::uint8_t *mac() const { return m_mac; }

      inline std::uint64_t timestamp() const { return bswap_64(m_timestamp); }
      inline void timestamp(std::uint64_t ts) { m_timestamp = bswap_64(ts); }

      inline std::uint32_t remote_verification_tag() const { return ntohl(m_remote_verification_tag); }
      inline void remote_verification_tag(std::uint32_t t) { m_remote_verification_tag = htonl(t); }

      inline std::uint32_t local_verification_tag() const { return ntohl(m_local_verification_tag); }
      inline void local_verification_tag(std::uint32_t t) { m_local_verification_tag = htonl(t); }

      inline std::uint32_t remote_tsn() const { return ntohl(m_remote_tsn); }
      inline void remote_tsn(std::uint32_t n) { m_remote_tsn = htonl(n); }

      inline std::uint32_t local_tsn() const { return ntohl(m_local_tsn); }
      inline void local_tsn(std::uint32_t n) { m_local_tsn = htonl(n); }

      inline std::uint32_t remote_rwnd() const { return ntohl(m_remote_rwnd); }
      inline void remote_rwnd(std::uint32_t r) { m_remote_rwnd = htonl(r); }

      inline std::uint32_t local_rwnd() const { return ntohl(m_local_rwnd); }
      inline void local_rwnd(std::uint32_t l) { m_local_rwnd = htonl(l); }

      inline std::uint16_t address_count() const { return ntohs(m_address_count); }
      inline void address_count(std::uint16_t c) { m_address_count = htons(c); }

      inline std::uint16_t ib_streams() const { return ntohs(m_ib_streams); }
      inline void ib_streams(std::uint16_t s) { m_ib_streams = htons(s); }

      inline std::uint16_t ob_streams() const { return ntohs(m_ob_streams); }
      inline void ob_streams(std::uint16_t s) { m_ob_streams = htons(s); }

    private:
      std::uint8_t m_mac[SHA256_DIGEST_LENGTH];
      std::uint64_t m_timestamp;

      std::uint32_t m_remote_verification_tag, m_local_verification_tag;
      std::uint32_t m_remote_tsn, m_local_tsn;
      std::uint32_t m_remote_rwnd, m_local_rwnd;
      std::uint16_t m_ib_streams, m_ob_streams;
      std::uint16_t m_address_count;
    } __attribute__((packed));

    class UnrecognizedParameter : public Parameter {
    public:
      UnrecognizedParameter(const Parameter &p);

      static std::size_t size(const Parameter &p);

    private:
      char m_data[];
    };

    class StateCookie : public Parameter {
    public:
      StateCookie(const InitChunk &in_response_to,
                  const InitAckChunk &response,
                  std::uint64_t mac_time,
                  const std::uint8_t *mac_key, std::size_t mac_key_len);

    protected:
      // TODO for WebRTC, we don't care about transport addresses, but
      // we should probably think about supporting them?
      StateCookieData m_cookie;
    };

    typedef ChunkIterator<SctpHeaderPtr, SctpChunkHeader> SctpChunkIterator;

    class SctpHeaderPtr : public HeaderPtr<SctpHeader, SctpChunkHeader> {
    public:
      inline SctpHeaderPtr(std::vector<std::uint8_t> &raw_data)
        : HeaderPtr<SctpHeader, SctpChunkHeader>(raw_data) {
      }

      inline SctpHeaderPtr(std::uint8_t *buf, std::size_t sz)
        : HeaderPtr<SctpHeader, SctpChunkHeader>(buf, sz) {
      }

      std::uint32_t expected_checksum() const;
      inline bool verify_checksum() const { return (*this)->actual_checksum() == expected_checksum(); }
    };

    class SctpPacketBuilder {
    public:
      inline SctpPacketBuilder() {
        reset(0, 0, 0);
      }
      SctpPacketBuilder(SctpHeaderPtr hdr, std::size_t mtu);
      SctpPacketBuilder(std::uint16_t from_port, std::uint16_t to_port,
                        std::size_t mtu);

      void reset(SctpHeaderPtr hdr, std::size_t mtu);
      void reset(std::uint16_t from_port, std::uint16_t to_port, std::size_t mtu);
      void finish();

      inline boost::asio::const_buffer asio_buffer() const {
        return boost::asio::buffer(m_data.data(), m_size);
      }
      inline bool overflow() const { return m_overflow; }

      inline bool has_chunks() const {
        return m_size > sizeof(SctpHeader);
      }

      inline SctpHeader &header() { return *((SctpHeader *) m_data.data()); }

      template<typename T>
      void write_chunk(const T& chunk) {
        if ( !m_overflow ) {
          if ( (m_size + sizeof(T)) >= m_data.size() )
            m_overflow = true;
          else {
            T *cur((T *) (m_data.data() + m_size));
            m_size += sizeof(*cur);

            new (cur) T(chunk);

            m_last_chunk = &(cur->header());
          }
        }
      }

      template<typename T, typename... Args>
      void emplace_chunk(const Args& ...args) {
        if ( !m_overflow ) {
          std::size_t expected_size(T::size(args...));
          if ( (m_size + expected_size) >= m_data.size() )
            m_overflow = true;
          else {
            char *cur((char *) m_data.data() + m_size);
            m_size += expected_size;

            new (cur) T(args...);

            m_last_chunk = &(((T *)cur)->header());
          }
        }
      }

      template<typename T>
      void write_parameter(const T& p) {
        if ( !m_overflow && m_last_chunk) {
          if ( (m_size + p.padded_size()) >= m_data.size() ) {
            m_overflow = true;
            m_last_chunk = nullptr;
          } else {
            T *cur((T *) (m_data.data() + m_size));
            m_size += p.padded_size();

            new (cur) T(p);
            m_last_chunk->resize(m_last_chunk->raw_size() + p.padded_size());
          }
        }
      }

      template<typename T, typename... Args>
      void emplace_parameter(const Args& ...args) {
        if ( !m_overflow && m_last_chunk ) {
          std::size_t padded_size(T::size(args...));
          padded_size = 4 * ((padded_size + 3) / 4);

          if ( (m_size + padded_size) >= m_data.size() ) {
            m_overflow = true;
            m_last_chunk = nullptr;
          } else {
            void *cur(m_data.data() + m_size);
            m_size += padded_size;

            new (cur) T(args...);
            m_last_chunk->resize(m_last_chunk->raw_size() + padded_size);
          }
        }
      }

    private:
      std::vector<std::uint8_t> m_data;
      std::size_t m_size;

      SctpChunkHeader *m_last_chunk;
      bool m_overflow;
    };
  }
}

namespace std {
  template<>
  struct iterator_traits<stork::sctp::SctpChunkIterator> {
    typedef int difference_type;
    typedef std::forward_iterator_tag iterator_category;
  };
}

#endif
