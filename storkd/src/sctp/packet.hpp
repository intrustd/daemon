#ifndef __stork_sctp_packet_HPP__
#define __stork_sctp_packet_HPP__

#include <boost/asio.hpp>
#include <vector>
#include <functional>

#include "manager.hpp"
#include "proto.hpp"

namespace stork {
  namespace sctp {
    class SctpChunkProcessor : public ISctpChunkHandler {
    public:
      SctpChunkProcessor(SctpManagerBase &mgr, SctpPacketBuilder &response,
                         const boost::asio::ip::address &source,
                         SctpHeaderPtr hdr);

      virtual void init_chunk(InitChunk &chunk) override;
      virtual void data_chunk(DataChunk &chunk) override;
      virtual void cookie_echo(CookieEcho &echo) override;
      virtual void unknown_chunk_type(SctpChunkHeader &chunk) override;

      bool process();

    private:
      void on_chunk();
      bool verify_tag(std::uint32_t expected);

      void out_of_resources();
      void refuse_association();
      void unverified_tag();
      void invalid_association();

      inline bool is_processing_packets() const {
        return !m_has_errored;
      }

      SctpManagerBase &m_manager;
      boost::asio::ip::address m_source;
      SctpHeaderPtr m_packet;

      bool m_has_seen_init, m_has_seen_packets, m_has_errored, m_has_response;

      SctpPacketBuilder &m_response;

      std::shared_ptr<SctpOpenPort> m_destination_port;
      std::shared_ptr<SctpAssociationControlBase> m_association;
    };
  }
}

#endif
