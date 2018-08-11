#include <boost/bind.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/manipulators/dump.hpp>
#include <boost/thread/lock_factories.hpp>
#include <mutex>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../random.hpp"
#include "dtls.hpp"

namespace stork {
  namespace peer {

    static void new_ptr(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                        int idx, long argl, void *argp) {
    }
    #define free_ptr new_ptr

    static int dup_ptr(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
                       void *from_d, int idx, long argl, void *argp) {
      return 0;
    }

    class DTLSHelpers {
    public:
      static int generate_cookie_trampoline(SSL *conn, unsigned char *cookie,
                                            unsigned int *cookie_len) {
        BOOST_LOG_TRIVIAL(debug) << "Generate cookie trampoline";

        SSL_CTX *ssl_ctx(SSL_get_SSL_CTX(conn));
        auto channel((DTLSChannel *) SSL_get_ex_data(conn, DTLSChannel::m_ssl_data_index));
        auto ctx((DTLSContext *) SSL_CTX_get_ex_data(ssl_ctx, DTLSContext::m_ssl_ctx_data_index));

        if ( !ctx ) {
          BOOST_LOG_TRIVIAL(error) << "No DTLSContext available when generating cookie";
          return 0;
        } else if ( !channel ) {
          BOOST_LOG_TRIVIAL(error) << "No DTLSChannel available in SSL object";
          return 0;
        } else {
          if ( ctx->gen_cookie(channel, cookie, cookie_len) )
            return 1;
          else
            return 0;
        }
      }

      static int verify_cookie_trampoline(SSL *conn, const unsigned char *cookie,
                                          unsigned int cookie_len) {
        SSL_CTX *ssl_ctx(SSL_get_SSL_CTX(conn));
        auto channel((DTLSChannel *) SSL_get_ex_data(conn, DTLSChannel::m_ssl_data_index));
        auto ctx((DTLSContext *) SSL_CTX_get_ex_data(ssl_ctx, DTLSContext::m_ssl_ctx_data_index));

        if ( !ctx ) {
          BOOST_LOG_TRIVIAL(error) << "No DTLSContext available when generating cookie";
          return 0;
        } else if ( !channel ) {
          BOOST_LOG_TRIVIAL(error) << "No DTLSChannel available in SSL object";
          return 0;
        } else {
          if ( ctx->verify_cookie(channel, cookie, cookie_len) )
            return 1;
          else
            return 0;
        }
      }

      static int verify_peer(int preverify_ok, X509_STORE_CTX *ctx) {
        auto ssl((SSL *)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
        auto ssl_ctx((SSL_CTX *)SSL_get_SSL_CTX(ssl));
        auto channel((DTLSChannel *) SSL_get_ex_data(ssl, DTLSChannel::m_ssl_data_index));
        auto dtls_ctx((DTLSContext *) SSL_CTX_get_ex_data(ssl_ctx, DTLSContext::m_ssl_ctx_data_index));

        if ( !dtls_ctx ) {
          BOOST_LOG_TRIVIAL(error) << "No DTLSContext available in SSL_CTX object";
          return 0;
        }

        if ( !channel ) {
          BOOST_LOG_TRIVIAL(error) << "No DTLSChannel available in SSL object";
          return 0;
        }

        X509 *peer_cert_raw(X509_STORE_CTX_get_current_cert(ctx));
        if ( !peer_cert_raw ) {
          BOOST_LOG_TRIVIAL(error) << "No certificate available";
          return 0;
        }

        X509Certificate peer_cert(peer_cert_raw);
        if ( dtls_ctx->verify_peer_cert(channel, peer_cert) )
          return 1;
        else
          return 0;
      }
    };

    DTLSContext::DTLSContext(bool is_server)
      : m_ssl_ctx(nullptr) {
      m_ssl_ctx = SSL_CTX_new(is_server ? DTLS_server_method() : DTLS_client_method());
      if ( !m_ssl_ctx ) {
        BOOST_LOG_TRIVIAL(error) << "DTLS Context could not be created because we could not create an SSL context";
        throw std::bad_alloc();
      }

      if ( !SSL_CTX_set_ex_data(m_ssl_ctx, m_ssl_ctx_data_index, this) ) {
        BOOST_LOG_TRIVIAL(error) << "Could not set user data on SSL context";
        throw std::bad_alloc();
      }

      // Add all ciphers
      if ( !SSL_CTX_set_cipher_list(m_ssl_ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH") ) {
        BOOST_LOG_TRIVIAL(error) << "Set ciphers failed";
        ERR_print_errors_fp(stderr);
        throw std::bad_alloc();
      }

      // Generate SSL cookie
      std::copy(util::random_iterator<unsigned char>(m_ssl_cookie_base.size()),
                util::random_iterator<unsigned char>(),
                m_ssl_cookie_base.begin());

      // Set cookie callbacks
      SSL_CTX_set_cookie_generate_cb(m_ssl_ctx, DTLSHelpers::generate_cookie_trampoline);
      SSL_CTX_set_cookie_verify_cb(m_ssl_ctx, DTLSHelpers::verify_cookie_trampoline);
      SSL_CTX_set_verify(m_ssl_ctx, SSL_VERIFY_PEER, DTLSHelpers::verify_peer);
    }

    DTLSContext::~DTLSContext() {
      if ( m_ssl_ctx ) SSL_CTX_free(m_ssl_ctx);
    }

    void DTLSContext::complete_setup() {
      // Set the certificate and privatekey
      const X509Certificate &cert(ssl_certificate());
      if ( !SSL_CTX_use_PrivateKey(m_ssl_ctx, cert.raw_private_key()) ) {
        BOOST_LOG_TRIVIAL(error) << "Could not use private key";
        ERR_print_errors_fp(stderr);
        throw std::bad_alloc();
      }

      if ( !SSL_CTX_use_certificate(m_ssl_ctx, cert.raw_certificate()) ) {
        BOOST_LOG_TRIVIAL(error) << "Could not use certificate";
        ERR_print_errors_fp(stderr);
        throw std::bad_alloc();
      }
    }

    int DTLSContext::m_ssl_ctx_data_index(0);
    void DTLSContext::setup_ssl() {
      m_ssl_ctx_data_index = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_CTX, 0, 0,
                                                     new_ptr, dup_ptr, free_ptr);
      if ( m_ssl_ctx_data_index < 0 )
        throw std::bad_alloc();
    }

    bool DTLSContext::gen_cookie(DTLSChannel *c, unsigned char *cookie, unsigned int *cookie_len) {
      BOOST_LOG_TRIVIAL(debug) << "Doing generate: " << m_ssl_cookie_base.size();
      *cookie_len = m_ssl_cookie_base.size();
      std::copy(m_ssl_cookie_base.begin(), m_ssl_cookie_base.end(), cookie);
      return true;
    }

    bool DTLSContext::verify_cookie(DTLSChannel *c, const unsigned char *cookie, unsigned int cookie_len) {
      return cookie_len <= m_ssl_cookie_base.size() &&
        std::equal(cookie, cookie + cookie_len, m_ssl_cookie_base.begin());
    }

    // DTLSChannelOp
    DTLSChannelOp::~DTLSChannelOp() {
    }

    // DTLSChannel
    DTLSChannel::DTLSChannel(const DTLSContext &ctxt, std::function<void()> on_send)
      : m_dtls_context(ctxt), m_on_send(on_send), m_ssl_conn(nullptr), m_io(nullptr) {

      BIO *ssl_io;
      if ( !BIO_new_bio_pair(&ssl_io, 8192, &m_io, 8192) ) {
        ERR_print_errors_fp(stderr);
        throw std::bad_alloc();
      }
      m_ssl_conn = SSL_new(ctxt.ssl_context());
      if ( !m_ssl_conn )
        throw std::bad_alloc();

      SSL_set_bio(m_ssl_conn, ssl_io, ssl_io);

      if ( !SSL_set_ex_data(m_ssl_conn, m_ssl_data_index, this) ) {
        BOOST_LOG_TRIVIAL(error) << "Could not set user data on SSL connection";
        throw std::bad_alloc();
      }
    }

    DTLSChannel::~DTLSChannel() {
      if ( m_ssl_conn ) SSL_free(m_ssl_conn);
      if ( m_io ) BIO_free(m_io);
    }

    void DTLSChannel::cancel() {
      OpsQueue queue;
      std::swap(m_ops_queue, queue);

      auto &svc(service());
      for ( auto op : queue )
        op->cancel(svc);
    }

    int DTLSChannel::m_ssl_data_index(0);
    void DTLSChannel::setup_ssl() {
      m_ssl_data_index = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL, 0, 0,
                                                 new_ptr, dup_ptr, free_ptr);
      if ( m_ssl_data_index < 0 )
        throw std::bad_alloc();
    }

    bool DTLSChannel::push_datagram(const boost::asio::const_buffer &b) {
      boost::unique_lock l(m_conn_mutex);
      auto bytes_available(BIO_ctrl_get_write_guarantee(m_io));
      assert(boost::asio::buffer_size(b) < bytes_available);

      if ( bytes_available == 0 ) {
        BOOST_LOG_TRIVIAL(debug) << "Ignoring datagram because there is no space in our buffers";
        return BIO_ctrl_pending(m_io) > 0;
      }

      if ( m_ops_queue.empty() || !m_ops_queue.top()->waiting_on_read() ) {
        BOOST_LOG_TRIVIAL(debug) << "Ignoring datagram because there is no operation";
        return BIO_ctrl_pending(m_io) > 0;
      }

      auto bytes_written(BIO_write(m_io, boost::asio::buffer_cast<const char*>(b), boost::asio::buffer_size(b)));
      assert(bytes_written == (int) boost::asio::buffer_size(b));

      perform_read_op();

      return BIO_ctrl_pending(m_io) > 0;
    }

    bool DTLSChannel::has_outgoing_datagram() {
      boost::unique_lock l(m_conn_mutex);
      return BIO_ctrl_pending(m_io) > 0;
    }

    boost::asio::const_buffer DTLSChannel::next_outgoing_datagram() {
      boost::unique_lock l(m_conn_mutex);

      auto bytes_ready(BIO_pending(m_io));
      auto bytes_read(BIO_read(m_io, m_buffer.data(), bytes_ready));
      assert(bytes_read == bytes_ready);

      perform_write_op();

      return boost::asio::buffer(m_buffer.data(), bytes_read);
    }

    void DTLSChannel::perform_write_op() {
      if ( !m_ops_queue.empty() ) {
        if ( m_ops_queue.top()->waiting_on_write() )
          perform_op();
      }
    }

    void DTLSChannel::perform_read_op() {
      if ( !m_ops_queue.empty() ) {
        if ( m_ops_queue.top()->waiting_on_read() )
          perform_op();
      }
    }

    void DTLSChannel::perform_op() {
      if ( !m_ops_queue.empty() ) {
        auto result((*m_ops_queue.top())(m_ssl_conn, m_dtls_context.service()));
        switch ( result ) {
        default:
          BOOST_LOG_TRIVIAL(error) << "Unknown error";
        case DTLSChannelOp::fault:
          BOOST_LOG_TRIVIAL(error) << "Operation faulted channel. Shutting down (TODO)";
          // TODO shut down operation
          m_ops_queue.pop();
          break;
        case DTLSChannelOp::completes:
          m_ops_queue.pop();
          break;
        case DTLSChannelOp::needs_read:
          m_ops_queue.top()->set_wait(true, false);
          break;
        case DTLSChannelOp::needs_write:
          m_ops_queue.top()->set_wait(false, true);
          break;
        }
      }
    }

    void DTLSChannel::swap(DTLSChannel &c) noexcept {
      std::scoped_lock locked(c.m_conn_mutex, m_conn_mutex);
      std::swap(m_ops_queue, c.m_ops_queue);
      std::swap(m_ssl_conn, c.m_ssl_conn);
      std::swap(m_io, c.m_io);
      std::swap(m_buffer, c.m_buffer);
    }

    // DTLSv1ListenOp
    class DTLSv1ListenOp : public DTLSChannelOp {
    public:
      DTLSv1ListenOp(BIO_ADDR *addr, std::function<void(boost::system::error_code)> completion)
        : m_addr(addr), m_completion(completion) {
        set_wait(true, false);
      }
      virtual ~DTLSv1ListenOp() { };

      virtual Priority priority() const { return priority_dtls_normal; }

      virtual Result operator() (SSL *ssl, boost::asio::io_service &svc) {
        BOOST_LOG_TRIVIAL(debug) << "Running DTLS listen";
        int r(DTLSv1_listen(ssl, m_addr));
        if ( r > 0 ) {
          BOOST_LOG_TRIVIAL(debug) << "DTLSv1_listen: success!";
          svc.post(boost::bind(m_completion, boost::system::error_code()));
          return completes;
        } else if ( r < 0 ) {
          BOOST_LOG_TRIVIAL(error) << "DTLSv1_listen: failed";
          ERR_print_errors_fp(stderr);
          // TODO better error messages
          return_error(svc, ENOTRECOVERABLE);
          return fault;
        } else if ( r == 0 ) {
          // Wait
          int err(SSL_get_error(ssl, r));
          switch ( err ) {
          case SSL_ERROR_WANT_READ:
            return needs_read;
          case SSL_ERROR_WANT_WRITE:
            return needs_write;
          case SSL_ERROR_SYSCALL: {
            auto ec(errno);
            BOOST_LOG_TRIVIAL(error) << "DTLSv1_listen: syscall failed: " << ec;
            return needs_read;
          }
          case SSL_ERROR_SSL:
            BOOST_LOG_TRIVIAL(error) << "DTLSv1_listen: protocol error";
            ERR_print_errors_fp(stderr);
            return_error(svc, ENOTRECOVERABLE);
            return fault;
          case SSL_ERROR_WANT_ACCEPT:
          case SSL_ERROR_WANT_CONNECT:
            BOOST_LOG_TRIVIAL(error) << "DTLSv1_listen: wants accept/connect";
          default:
            return_error(svc, ENOTRECOVERABLE);
            return fault;
          }
        }

        return_error(svc, ENOTRECOVERABLE);
        return fault;
      }

      virtual void cancel(boost::asio::io_service &svc) {
        return_error(svc, ECONNABORTED);
      }

    private:
      void return_error(boost::asio::io_service &svc, int errno_) {
        svc.post(boost::bind(m_completion, boost::system::error_code(errno_, boost::system::generic_category())));
      }

      BIO_ADDR *m_addr;
      std::function<void(boost::system::error_code)> m_completion;
    };

    class SSLAcceptOp : public DTLSChannelOp {
    public:
      SSLAcceptOp(std::function<void(boost::system::error_code)> completion)
        : m_completion(completion) {
        set_wait(true, false);
      }

      virtual ~SSLAcceptOp() { };

      virtual Priority priority() const { return priority_dtls_normal; }
      virtual Result operator () (SSL *ssl, boost::asio::io_service &svc) {
        BOOST_LOG_TRIVIAL(debug) << "Running SSL accept";
        int r(SSL_accept(ssl));
        if ( r > 0 ) {
          BOOST_LOG_TRIVIAL(debug) << "SSL accept: success!";
          svc.post(boost::bind(m_completion, boost::system::error_code()));
          return completes;
        } else if ( r == 0 ) {
          BOOST_LOG_TRIVIAL(error) << "SSL_accept: shutdown";
          ERR_print_errors_fp(stderr);
          // TODO better error messages
          return_error(svc, ENOTRECOVERABLE);
          return fault;
        } else if ( r < 0 ) {
          int err(SSL_get_error(ssl, r));
          switch ( err ) {
          case SSL_ERROR_WANT_READ:
            return needs_read;
          case SSL_ERROR_WANT_WRITE:
            return needs_write;
          case SSL_ERROR_SYSCALL: {
            auto ec(errno);
            BOOST_LOG_TRIVIAL(error) << "SSL_accept: syscall failed: " << ec;
            return needs_read;
          }
          case SSL_ERROR_SSL:
            BOOST_LOG_TRIVIAL(error) << "SSL_accept: protocol error";
            ERR_print_errors_fp(stderr);
            // TODO better error messages
            return_error(svc, ENOTRECOVERABLE);
            return fault;
          default:
            // TODO better error messages
            return_error(svc, ENOTRECOVERABLE);
            return fault;
          }
        }

        return_error(svc, ENOTRECOVERABLE);
        return fault;
      }

      virtual void cancel(boost::asio::io_service &svc) {
        return_error(svc, ECONNABORTED);
      }

    private:
      void return_error(boost::asio::io_service &svc, int errno_) {
        svc.post(boost::bind(m_completion, boost::system::error_code(errno_, boost::system::generic_category())));
      }

      std::function<void(boost::system::error_code)> m_completion;
    };

    //DTLSServer
    DTLSServer::DTLSServer(const DTLSContext &ctxt, std::function<void()> on_send)
      : DTLSChannel(ctxt, on_send), m_bio_addr(nullptr) {
      m_bio_addr = BIO_ADDR_new();
      if ( !m_bio_addr )
        throw std::bad_alloc();

      // Add listen and accept op
      start_listen();
    }

    DTLSServer::~DTLSServer() {
      if ( m_bio_addr ) BIO_ADDR_free(m_bio_addr);
    }

    void DTLSServer::swap(DTLSServer &s) noexcept {
      DTLSChannel::swap(s);
    }

    void DTLSServer::start_listen() {
      submit_op<DTLSv1ListenOp>(m_bio_addr, boost::bind(&DTLSServer::listen_completes, this, boost::placeholders::_1));
    }

    void DTLSServer::listen_completes(boost::system::error_code ec) {
      if ( ec ) {
        BOOST_LOG_TRIVIAL(error) << "Listen operation failed. Going to try again: " << ec;
        // TODO limit number of retries
        start_listen();
      } else {
        submit_op<SSLAcceptOp>(boost::bind(&DTLSServer::connection_ready, this, boost::placeholders::_1));
      }
    }

    void DTLSServer::connection_ready(boost::system::error_code ec) {
      if ( ec ) {
        BOOST_LOG_TRIVIAL(error) << "Can't read anymore";
      }
    }

//    void DTLSServer::on_read_packet(boost::system::error_code ec, std::size_t bytes_sent) {
//      if ( ec ) {
//        BOOST_LOG_TRIVIAL(error) << "Can't read a packet: " << ec;
//      } else {
//        BOOST_LOG_TRIVIAL(debug) << "Received decrypted packet data: " << boost::log::dump(m_test_buffer, bytes_sent);
//
//        submit_op<SSLReadOp>(boost::asio::buffer(m_test_buffer, sizeof(m_test_buffer)),
//                             boost::bind(&DTLSServer::on_read_packet, this, boost::placeholders::_1, boost::placeholders::_2));
//      }
//    }
  }
}
