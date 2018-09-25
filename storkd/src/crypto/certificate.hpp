#ifndef __stork_crypto_certificate_HPP__
#define __stork_crypto_certificate_HPP__

#include <boost/filesystem.hpp>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>

namespace stork {
  namespace peer { class DTLSContext; }
  namespace crypto {
    typedef int CurveName;

    class Key {
    public:
      Key();
      Key(CurveName curve);
      Key(const Key &kp);
      ~Key();

      void generate(CurveName curve = NID_X9_62_prime256v1);

      inline bool valid() const { return m_private_key; }

      Key &operator =(const Key &kp);
      void reset();

      void read_pem_from_file(const boost::filesystem::path &path, std::error_code &ec);
      void write_pem_to_file(const boost::filesystem::path &path);

      void from_asn1_encoded_public_key(const char *data, std::size_t data_size);

      inline EVP_PKEY *raw_key() const { return m_private_key; }
    private:
      EC_KEY *m_curve;
      EVP_PKEY *m_private_key;
    };

    class X509Certificate {
    public:

      X509Certificate();
      X509Certificate(CurveName curve);
      X509Certificate(X509 *x);
      X509Certificate(const X509Certificate &c);
      ~X509Certificate();

      void generate(CurveName curve = NID_X9_62_prime256v1);

      inline bool valid () const {
        return m_certificate;
      }

      inline bool has_private_key() const {
        return valid() && m_privkey.valid();
      }

      X509Certificate &operator =(const X509Certificate &c);

      // h must have enough space for 256 bits (i.e. 32 bytes)
      bool sha256_fingerprint(std::uint8_t *h) const;

      void reset();

    protected:
      inline X509 *raw_certificate() const { return m_certificate; }
      inline EVP_PKEY *raw_private_key() const { return m_privkey.raw_key(); }

      friend class ::stork::peer::DTLSContext;

    private:
      Key m_privkey;
      X509 *m_certificate;
    };
  }
}

#endif
