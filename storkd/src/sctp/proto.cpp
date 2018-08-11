#include <boost/crc.hpp>
#include <boost/log/trivial.hpp>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <algorithm>

#include "proto.hpp"

namespace stork {
  namespace sctp {
    typedef boost::crc_optimal<32, 0x1EDC6F41, 0xFFFFFFFF, 0xFFFFFFFF, true, true> crc_32_c_type;

    std::uint32_t SctpHeaderPtr::expected_checksum() const {
      crc_32_c_type crc;

      void *raw((void *)buffer());
      crc.process_block(raw, (void *) ((std::uint8_t *)raw + 8));

      std::uint32_t zero(0);
      crc.process_block((void *)&zero, (void *)((std::uintptr_t) &zero + sizeof(zero)));

      crc.process_block((void *) (buffer() + 12), buffer() + buffer_size());

      return crc.checksum();
    }

    void SctpChunkHeader::dispatch(ISctpChunkHandler &handle) {
      switch ( chunk_type() ) {
      case INIT:
        handle.init_chunk(data<InitChunk>());
        break;
      case COOKIE_ECHO:
        handle.cookie_echo(data<CookieEcho>());
        break;
      case DATA:
        handle.data_chunk(data<DataChunk>());
        break;
      default:
        handle.unknown_chunk_type(*this);
        break;
      }
    }

    //StateCookie
    void StateCookieData::calculate_mac(const std::uint8_t *key, std::size_t key_len, std::uint8_t *out) {
      unsigned int out_size(sizeof(m_mac));
      if ( !HMAC(EVP_sha256(), (void *)key, key_len,
                 (const unsigned char *)this, sizeof(*this),
                 out, &out_size) )
        throw std::bad_alloc();
    }

    bool StateCookieData::verify_mac(const std::uint8_t *key, std::size_t key_len) {
      std::uint8_t actual_mac[SHA256_DIGEST_LENGTH], expected_mac[SHA256_DIGEST_LENGTH];
      std::copy(m_mac, m_mac + SHA256_DIGEST_LENGTH, actual_mac);
      std::fill(m_mac, m_mac + SHA256_DIGEST_LENGTH, 0);

      calculate_mac(key, key_len, expected_mac);

      std::copy(actual_mac, actual_mac + SHA256_DIGEST_LENGTH, m_mac);

      return std::equal(actual_mac, actual_mac + SHA256_DIGEST_LENGTH, expected_mac);
    }

    StateCookie::StateCookie(const InitChunk &in_response_to,
                             const InitAckChunk &response,
                             std::uint64_t mac_time,
                             const std::uint8_t *mac_key, std::size_t mac_key_len)
      : Parameter(STATE_COOKIE, sizeof(*this)) {

      std::fill(m_cookie.mac(), m_cookie.mac() + SHA256_DIGEST_LENGTH, 0);
      m_cookie.timestamp(mac_time);
      m_cookie.remote_verification_tag(in_response_to.initiate_tag());
      m_cookie.local_verification_tag(response.initiate_tag());
      m_cookie.remote_tsn(in_response_to.initial_tsn());
      m_cookie.local_tsn(response.initial_tsn());
      m_cookie.remote_rwnd(in_response_to.a_rwnd());
      m_cookie.local_rwnd(response.a_rwnd());
      m_cookie.ib_streams(response.num_inbound());
      m_cookie.ob_streams(response.num_outbound());
      m_cookie.address_count(0);

      std::uint8_t mac[SHA256_DIGEST_LENGTH];
      m_cookie.calculate_mac(mac_key, mac_key_len, mac);
      std::copy(mac, mac + sizeof(mac), m_cookie.mac());
    }

    UnrecognizedParameter::UnrecognizedParameter(const Parameter &p)
      : Parameter(UNRECOGNIZED_PARAMETER, size(p)) {
      char *p_ptr((char *) &p);
      std::copy(p_ptr, p_ptr + p.raw_size(), m_data);
    }

    std::size_t UnrecognizedParameter::size(const Parameter &p) {
      return sizeof(UnrecognizedParameter) + p.raw_size();
    }

    // SctpChunkPrinter
    void SctpChunkPrinter::init_chunk(InitChunk &chunk) {
      BOOST_LOG_TRIVIAL(error) << "INIT chunk of size " << chunk.header().padded_size();
      BOOST_LOG_TRIVIAL(error) << "     Initiate tag: " << chunk.initiate_tag();
      BOOST_LOG_TRIVIAL(error) << "           a rwnd: " << chunk.a_rwnd();
      BOOST_LOG_TRIVIAL(error) << " Outbound streams: " << chunk.num_outbound();
      BOOST_LOG_TRIVIAL(error) << "  Inbound streams: " << chunk.num_inbound();
      BOOST_LOG_TRIVIAL(error) << "      Initial TSN: " << chunk.initial_tsn();

      for ( auto &p : chunk ) {
        BOOST_LOG_TRIVIAL(error) << "        Parameter: " << p.type() << " of size " << p.padded_size();
      }
    }

    void SctpChunkPrinter::unknown_chunk_type(SctpChunkHeader &chunk) {
      BOOST_LOG_TRIVIAL(error) << "Unknown chunk type " << chunk.chunk_type();
    }

    // SctpPacketBuilder
    SctpPacketBuilder::SctpPacketBuilder(SctpHeaderPtr hdr, std::size_t mtu) {
      reset(hdr, mtu);
    }

    SctpPacketBuilder::SctpPacketBuilder(std::uint16_t from_port, std::uint16_t to_port,
                                         std::size_t mtu) {
      reset(from_port, to_port, mtu);
    }

    void SctpPacketBuilder::reset(SctpHeaderPtr hdr, std::size_t mtu) {
      reset(hdr->destination_port(), hdr->source_port(), mtu);
    }

    void SctpPacketBuilder::reset(std::uint16_t from_port, std::uint16_t to_port, std::size_t mtu) {
      m_size = sizeof(SctpHeader);
      m_last_chunk = nullptr;
      m_overflow = false;

      mtu = std::max(sizeof(SctpHeader), mtu);
      m_data.resize(mtu);

      header().source_port(from_port);
      header().destination_port(to_port);
    }

    void SctpPacketBuilder::finish() {
      SctpHeaderPtr hdr(m_data.data(), m_size);
      header().checksum(hdr.expected_checksum());
    }
  }
}
