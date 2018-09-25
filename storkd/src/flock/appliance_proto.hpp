#ifndef __appliance_proto_HPP__
#define __appliance_proto_HPP__

#include <arpa/inet.h>

#include "../crypto/certificate.hpp"

namespace stork {
  namespace flock {
    struct ApplianceMessage {
    public:
      static constexpr std::uint32_t APPLIANCE_MAGIC = 0xDEADBEEF;

      static ApplianceMessage no_such_appliance(std::uint32_t ctag, std::uint32_t ptag);
      static ApplianceMessage no_such_connection(std::uint32_t ctag, std::uint32_t ptag);
      static ApplianceMessage confirm_candidate(std::uint32_t ctag, std::uint32_t ptag);

      bool verify_size(std::size_t sz) const;
      bool verify_message(const crypto::Key &kp) const;

      inline std::uint32_t magic() const { return ntohl(m_magic); }
      inline std::uint32_t connection_tag() const { return ntohl(m_connection_tag); }
      inline std::uint16_t payload_tag() const { return ntohs(m_payload_tag); }
      inline std::size_t total_size() const {
        return sizeof(*this) + ntohs(m_appliance_name_len) + ntohs(m_payload_len);
      }

      inline bool is_registration() const {
        return m_connection_tag == 0;
      }
      inline bool is_end_of_candidates() const {
        return m_payload_len == 0 && !is_registration();
      }

      inline std::string appliance_name() const {
        return std::string(m_data, m_data + ntohs(m_appliance_name_len));
      }

      inline std::string ice_candidate() const { return payload(); }
      inline std::string payload() const {
        const char *dat(m_data + ntohs(m_appliance_name_len));
        return std::string(dat, dat + ntohs(m_payload_len));
      }

      inline const char *raw_payload() const {
        return m_data + ntohs(m_appliance_name_len);
      }
      inline std::uint16_t payload_size() const {
        return ntohs(m_payload_len);
      }

    private:
      ApplianceMessage(std::uint32_t ctag, std::uint32_t ptag);

      static constexpr std::uint32_t FlagIsResponse = 0x1;
      static constexpr std::uint32_t FlagIsError    = 0x2;

      enum {
        NoSuchAppliance = 1,
        NoSuchConnection = 2
      } ErrorValue;

      std::uint8_t m_signature[32]; // SHA256 PKEY signature
      std::uint32_t m_magic; // 0xDEADBEEF
      std::uint32_t m_flags;
      std::uint32_t m_connection_tag;
      std::uint16_t m_payload_tag, m_appliance_name_len, m_payload_len;
      char m_data[];
    } __attribute__((packed));
  }
}

#endif
