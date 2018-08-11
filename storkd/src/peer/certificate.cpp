#include <boost/log/trivial.hpp>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <ctime>

#include "certificate.hpp"


namespace stork {
  namespace peer {
    X509Certificate::X509Certificate()
      : m_keypair(nullptr), m_privkey(nullptr),
        m_certificate(nullptr) {
    }

    X509Certificate::X509Certificate(CurveName c)
      : m_keypair(nullptr), m_privkey(nullptr),
        m_certificate(nullptr) {
      generate(c);
    }

    X509Certificate::X509Certificate(X509 *peer)
      : m_keypair(nullptr), m_privkey(nullptr),
        m_certificate(nullptr) {
      if ( !X509_up_ref(peer) )
        throw std::bad_alloc();

      m_certificate = peer;
    }

    X509Certificate::~X509Certificate() {
      reset();
    }

    void X509Certificate::reset() {
      // Order matters here
      if ( m_certificate ) X509_free(m_certificate);
      if ( m_privkey ) EVP_PKEY_free(m_privkey);
      if ( m_keypair ) EC_KEY_free(m_keypair);

      m_keypair = nullptr;
      m_privkey = nullptr;
      m_certificate = nullptr;
    }

    void X509Certificate::generate(CurveName curve) {
      reset();

      m_keypair = EC_KEY_new_by_curve_name(curve);
      if ( !m_keypair ) goto error;

      if ( !EC_KEY_generate_key(m_keypair) ) goto error;
      EC_KEY_set_asn1_flag(m_keypair, OPENSSL_EC_NAMED_CURVE);

      m_privkey = EVP_PKEY_new();
      if ( !m_privkey ) goto error;

      if ( !EVP_PKEY_set1_EC_KEY(m_privkey, m_keypair) ) goto error;

      m_certificate = X509_new();
      if ( !m_certificate ) goto error;

      BOOST_LOG_TRIVIAL(debug ) << "Made certificate";
      if ( !ASN1_INTEGER_set(X509_get_serialNumber(m_certificate), 1) ) goto error;

      ASN1_TIME *t;
      time_t now;
      t = ASN1_TIME_set(NULL, 0);
      X509_set_notBefore(m_certificate, t);

      time(&now);
      now += 3600 * 24; // One day
      t = ASN1_TIME_set(t, now);
      X509_set_notAfter(m_certificate, t);
      ASN1_STRING_free(t);
      t = NULL;

      //      X509_gmtime_adj(X509_get_notBefore(m_certificate), 0);
      //      X509_gmtime_adj(X509_get_notAfter(m_certificate), 0);
      BOOST_LOG_TRIVIAL(debug ) << "set serial number";

      if ( !X509_set_pubkey(m_certificate, m_privkey) ) goto error;
      BOOST_LOG_TRIVIAL(debug ) << "set public key";

      X509_NAME *name;
      name = X509_get_subject_name(m_certificate);
      if ( !name ) goto error;
      BOOST_LOG_TRIVIAL(debug ) << "got name";

      int err;
      err = X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"WebRTC", -1, -1, 0);
      if ( !err ) goto error;
      BOOST_LOG_TRIVIAL(debug ) << "Add C Entry" << err;

      if ( !X509_set_issuer_name(m_certificate, name) ) goto error;
      BOOST_LOG_TRIVIAL(debug ) << "Set issuer name";

      if ( !X509_sign(m_certificate, m_privkey, EVP_sha1()) ) goto error;
      BOOST_LOG_TRIVIAL(debug ) << "Signing";

      FILE *test;
      test = fopen("test-ssl-cert", "w");
      PEM_write_X509(test, m_certificate);
      fclose(test);
      return;

    error:
      BOOST_LOG_TRIVIAL(error) << "Error generating certificate";
      reset();
      return;
    }

    bool X509Certificate::sha256_fingerprint(std::uint8_t *h) const {
      std::shared_ptr<BIO> crt_bio(BIO_new(BIO_s_mem()), BIO_free_all);
      int err = i2d_X509_bio(crt_bio.get(), m_certificate);
      if ( err < 0 )
        return false;

      const unsigned char *der_data;
      unsigned long der_length;
      der_length = BIO_get_mem_data(crt_bio.get(), &der_data);

      SHA256(der_data, der_length, h);

      return true;
    }
  }
}
