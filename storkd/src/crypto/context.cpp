#include "context.hpp"

namespace stork {
  namespace crypto {
    KeyContext::KeyContext()
      : m_engine(nullptr), m_ctx(nullptr) {
    }

    KeyContext::KeyContext(const Key &c)
      : m_key(c), m_engine(nullptr), m_ctx(nullptr) {
      recreate();
    }

    KeyContext::~KeyContext() {
      reset();
    }

    void KeyContext::reset() {
      if ( m_ctx ) EVP_PKEY_CTX_free(m_ctx);
      if ( m_engine ) ENGINE_free(m_engine);
    }

    void KeyContext::recreate() {
      reset();

      m_engine = ENGINE_new();
      if ( !m_engine )
        return;

      m_ctx = EVP_PKEY_CTX_new(m_key.raw_key(), m_engine);
      if ( !m_ctx ) {
        reset();
        return;
      }
    }

    void KeyContext::decrypt(const std::uint8_t *in_data, std::size_t in_size,
                             std::uint8_t *out_data, std::size_t &out_size,
                             std::error_code &ec) {
      int err;

      ec = std::error_code();
      if ( !m_ctx ) {
        ec = std::make_error_code(std::errc::invalid_argument);
        return;
      }

      err = EVP_PKEY_decrypt_init(m_ctx);
      if ( err <= 0 ) {
        if ( err == -2 )
          ec = std::make_error_code(std::errc::not_supported);
        else
          ec = std::make_error_code(std::errc::invalid_argument);
        return;
      }

      err = EVP_PKEY_CTX_set_rsa_padding(m_ctx, RSA_PKCS1_PADDING);
      if ( err <= 0 ) {
        ec = std::make_error_code(std::errc::invalid_argument);
        return;
      }

      std::size_t real_size;
      err = EVP_PKEY_decrypt(m_ctx, nullptr, &real_size, in_data, in_size);
      if ( err <= 0 ) {
        if ( err == -2 )
          ec = std::make_error_code(std::errc::not_supported);
        else
          ec = std::make_error_code(std::errc::invalid_argument);
        return;
      }

      if ( real_size < out_size )
        out_size = real_size;
      else {
        ec = std::make_error_code(std::errc::not_enough_memory);
        return;
      }

      err = EVP_PKEY_decrypt(m_ctx, out_data, &out_size, in_data, in_size);
      if ( err <= 0 ) {
        ec = std::make_error_code(std::errc::invalid_argument);
        return;
      }
    }
  }
}
