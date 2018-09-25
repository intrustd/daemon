#include <boost/log/trivial.hpp>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <ctime>

#include "certificate.hpp"


namespace stork {
  namespace crypto {

    Key::Key()
      : m_curve(nullptr), m_private_key(nullptr) {
    }

    Key::Key(CurveName curve)
      : m_curve(nullptr), m_private_key(nullptr) {
      generate(curve);
    }

    Key::Key(const Key &kp)
      : m_curve(nullptr), m_private_key(nullptr) {
      *this = kp;
    }

    Key::~Key() {
      reset();
    }

    void Key::generate(CurveName curve) {
      m_curve = EC_KEY_new_by_curve_name(curve);
      if ( !m_curve ) goto error;

      if ( !EC_KEY_generate_key(m_curve) ) goto error;
      EC_KEY_set_asn1_flag(m_curve, OPENSSL_EC_NAMED_CURVE);

      m_private_key = EVP_PKEY_new();
      if ( !m_private_key ) goto error;

      if ( !EVP_PKEY_set1_EC_KEY(m_private_key, m_curve) ) goto error;

    error:
      BOOST_LOG_TRIVIAL(error) << "Error generating key pair";
      reset();
      return;
    }

    void Key::reset() {
      if ( m_private_key ) EVP_PKEY_free(m_private_key);
      if ( m_curve ) EC_KEY_free(m_curve);

      m_private_key = nullptr;
      m_curve = nullptr;
    }

    Key &Key::operator=(const Key &c) {
      reset();

      if ( c.m_curve ) {
        EC_KEY_up_ref(c.m_curve);
        m_curve = c.m_curve;
      }

      if ( c.m_private_key ) {
        EVP_PKEY_up_ref(c.m_private_key);
        m_private_key = c.m_private_key;
      }

      return *this;
    }

    void Key::read_pem_from_file(const boost::filesystem::path &path, std::error_code &ec) {
      reset();

      FILE *fp(fopen(path.string().c_str(), "rt"));
      m_private_key = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
      fclose(fp);

      if ( !m_private_key ) {
        ec = std::make_error_code(std::errc::invalid_argument);
        reset();
        return;
      }

      m_curve = EVP_PKEY_get1_EC_KEY(m_private_key);
      if ( !m_curve ) {
        ec = std::make_error_code(std::errc::invalid_argument);
        reset();
        return;
      }
    }

    void Key::write_pem_to_file(const boost::filesystem::path &path) {
      FILE *fp(fopen(path.string().c_str(), "wt"));
      int err = PEM_write_PrivateKey(fp, m_private_key, nullptr, nullptr, 0, nullptr, nullptr);
      fclose(fp);

      if ( err == 0 )
        BOOST_LOG_TRIVIAL(error) << "Could not write PEM file";
    }

    void Key::from_asn1_encoded_public_key(const char *data, std::size_t data_sz) {
      reset();

      m_private_key = d2i_PublicKey(EVP_PKEY_RSA, nullptr,
                                    (const unsigned char **) &data, data_sz);
      if ( !m_private_key ) {
        BOOST_LOG_TRIVIAL(error) << "Could not decode public key: " << ERR_get_error();
      }
    }

    // X509Certificate
    X509Certificate::X509Certificate()
      : m_certificate(nullptr) {
    }

    X509Certificate::X509Certificate(CurveName c)
      : m_certificate(nullptr) {
      generate(c);
    }

    X509Certificate::X509Certificate(X509 *peer)
      : m_certificate(nullptr) {
      if ( !X509_up_ref(peer) )
        throw std::bad_alloc();

      m_certificate = peer;
    }

    X509Certificate::X509Certificate(const X509Certificate &c)
      : m_certificate(nullptr) {
      *this = c;
    }

    X509Certificate::~X509Certificate() {
      reset();
    }

    void X509Certificate::reset() {
      // Order matters here
      if ( m_certificate ) X509_free(m_certificate);
      m_certificate = nullptr;

      m_privkey.reset();
    }

    void X509Certificate::generate(CurveName curve) {
      reset();

      m_privkey.generate();
      if ( !m_privkey.valid() ) goto error;

      m_certificate = X509_new();
      if ( !m_certificate ) goto error;

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

      if ( !X509_set_pubkey(m_certificate, m_privkey.raw_key()) ) goto error;

      X509_NAME *name;
      name = X509_get_subject_name(m_certificate);
      if ( !name ) goto error;

      int err;
      err = X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"WebRTC", -1, -1, 0);
      if ( !err ) goto error;
      BOOST_LOG_TRIVIAL(debug ) << "Add C Entry" << err;

      if ( !X509_set_issuer_name(m_certificate, name) ) goto error;
      BOOST_LOG_TRIVIAL(debug ) << "Set issuer name";

      if ( !X509_sign(m_certificate, m_privkey.raw_key(), EVP_sha1()) ) goto error;
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

    X509Certificate &X509Certificate::operator =(const X509Certificate &c) {
      reset();

      m_privkey = c.m_privkey;

      if ( c.m_certificate ) {
        X509_up_ref(c.m_certificate);
        m_certificate = c.m_certificate;
      }

      return *this;
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
