#ifndef __stork_peer_certificate_HPP__
#define __stork_peer_certificate_HPP__

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>

namespace stork {
  namespace peer {
    class X509Certificate {
    public:
      typedef int CurveName;

      X509Certificate();
      X509Certificate(CurveName curve);
      X509Certificate(X509 *x);
      ~X509Certificate();

      void generate(CurveName curve = NID_X9_62_prime256v1);

      inline bool valid () const {
        return m_certificate;
      }

      inline bool has_private_key() const {
        return valid() && m_keypair && m_privkey;
      }

      // h must have enough space for 256 bits (i.e. 32 bytes)
      bool sha256_fingerprint(std::uint8_t *h) const;

      void reset();

    protected:
      inline X509 *raw_certificate() const { return m_certificate; }
      inline EVP_PKEY *raw_private_key() const { return m_privkey; }

      friend class DTLSContext;

    private:
      EC_KEY *m_keypair;

      EVP_PKEY *m_privkey;
      X509 *m_certificate;
    };
  }
}

#endif
