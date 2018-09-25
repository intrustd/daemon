#ifndef __stork_crypto_context_HPP__
#define __stork_crypto_context_HPP__

#include <openssl/evp.h>
#include <openssl/engine.h>

#include "certificate.hpp"

namespace stork {
  namespace crypto {
    class KeyContext {
    public:
      KeyContext();
      KeyContext(const Key &c);
      ~KeyContext();

      inline bool valid() const { return m_key.valid() && m_ctx; }

      void decrypt(const std::uint8_t *in_data, std::size_t in_size,
                   std::uint8_t *out_data, std::size_t &out_size,
                   std::error_code &ec);
      void sign(const std::uint8_t *in_data, std::size_t in_size,
                std::uint8_t *digest, std::size_t &digest_size,
                std::error_code &ec);

      void reset();
      void recreate();

    private:
      Key m_key;

      ENGINE *m_engine;
      EVP_PKEY_CTX *m_ctx;
    };
  }
}

#endif
