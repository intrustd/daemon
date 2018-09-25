#include <boost/log/trivial.hpp>

#include "appliance_proto.hpp"

namespace stork {
  namespace flock {
    bool ApplianceMessage::verify_size(std::size_t sz) const {
      if ( sz < sizeof(*this) )
        return false;
      return sz >= total_size();
    }

    bool ApplianceMessage::verify_message(const crypto::Key &key) const {
      char digest[sizeof(m_signature)];
      std::size_t digest_len(sizeof(digest));
      std::error_code ec;

      ctx.sign((const std::uint8_t *) &m_magic, total_size() - sizeof(m_signature),
               digest, digest_len, ec);
      if ( ec ) {
        BOOST_LOG_TRIVIAL(error) << "Could not verify message: " << ec;
        return false;
      }

      return std::equal(m_signature, m_signature + sizeof(m_signature),
                        digest, digest + sizeof(digest));
    }
  }
}
