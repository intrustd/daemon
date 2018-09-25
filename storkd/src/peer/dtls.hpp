#ifndef __stork_peer_dtls_HPP__
#define __stork_peer_dtls_HPP__

#include <algorithm>
#include <cstdint>
#include <array>
#include <queue>
#include <memory>

#include <sys/types.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <boost/asio.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/heap/priority_queue.hpp>
#include <boost/log/trivial.hpp>

#include "../crypto/certificate.hpp"

namespace stork {
  namespace peer {
    enum dtls_error {
      dtls_success = 0,
      dtls_unknown,
      dtls_connection_closed,
      dtls_out_of_mem
    };

    class DTLSChannel;
    class DTLSContext {
    public:
      DTLSContext(bool is_server);
      virtual ~DTLSContext();

      inline SSL_CTX *ssl_context() const { return m_ssl_ctx; }

      virtual boost::asio::io_service &service() const =0;

      static void setup_ssl();

      template<typename T>
      T *user_data() const {
        return static_cast<T*>(SSL_CTX_get_ex_data(m_ssl_ctx, m_ssl_ctx_data_index));
      }


    protected:
      virtual const crypto::X509Certificate &ssl_certificate() const =0;

      virtual bool gen_cookie(DTLSChannel *c, unsigned char *cookie, unsigned int *cookie_len);
      virtual bool verify_cookie(DTLSChannel *c, const unsigned char *cookie, unsigned int cookie_len);
      virtual bool verify_peer_cert(DTLSChannel *c, const crypto::X509Certificate &cert) =0;

      void complete_setup();

      std::array<unsigned char, 128> m_ssl_cookie_base;

    private:
      SSL_CTX *m_ssl_ctx;

      static int m_ssl_ctx_data_index;

      friend class DTLSHelpers;
    };

    class DTLSChannelOp {
    public:
      inline DTLSChannelOp()
        : m_waiting_on_read(false),
          m_waiting_on_write(false) {
      }
      virtual ~DTLSChannelOp();

      enum Priority : std::uint8_t {
        priority_critical = 0,
        priority_dtls_high = 32,
        priority_dtls_normal = 64,
        priority_dtls_low = 96,
        priority_application_high = 128,
        priority_application_write = 150,
        priority_application_normal = 160,
        priority_application_low = 192
      };

      virtual Priority priority() const =0;

      enum Result {
        fault = 0,
        completes, // Completion has nothing to do with success or failure.
        needs_read,
        needs_write,
      };
      virtual Result operator() (SSL *ssl, boost::asio::io_service &svc) =0;
      virtual void cancel(boost::asio::io_service &svc) =0;

      inline void set_wait(bool wait_read, bool wait_write) {
        m_waiting_on_read = wait_read;
        m_waiting_on_write = wait_write;
      }
      inline bool waiting_on_read() const { return m_waiting_on_read; }
      inline bool waiting_on_write() const { return m_waiting_on_write; }

      class ComparePriority {
      public:
        template<typename HasPriority>
        inline bool operator() (const HasPriority &a,
                                const HasPriority &b) const {
          return a->priority() > b->priority();
        }
      };

    protected:
      bool m_waiting_on_read, m_waiting_on_write;
    };

    template<typename Completion>
    class SSLReadOp : public DTLSChannelOp {
    public:
      SSLReadOp(const boost::asio::mutable_buffer &buf,
                const Completion &completion)
        : m_buffer(boost::asio::buffer_cast<std::uint8_t *>(buf)),
          m_buffer_size(boost::asio::buffer_size(buf)),
          m_completion(completion) {
        set_wait(true, false);
      }

      ~SSLReadOp() {
      }

      virtual Priority priority() const { return priority_application_normal; }

      virtual Result operator() (SSL *ssl, boost::asio::io_service &svc) {
        //BOOST_LOG_TRIVIAL(debug) << "SSL_read: starting";
        int r(SSL_read(ssl, m_buffer, m_buffer_size));
        if ( r > 0 ) {
          //BOOST_LOG_TRIVIAL(debug) << "SSL_read: completes";
          svc.post(boost::bind<void>(m_completion, boost::system::error_code(), (std::size_t) r));
          return completes;
        } else {
          int err(SSL_get_error(ssl, r));
          //BOOST_LOG_TRIVIAL(debug) << "SSL_read: completes (waiting)";
          switch ( err ) {
          case SSL_ERROR_WANT_READ:
            return needs_read;
          case SSL_ERROR_WANT_WRITE:
            return needs_write;
          case SSL_ERROR_SYSCALL: {
            //auto ec(errno);
            //BOOST_LOG_TRIVIAL(error) << "SSL_read: syscall failed: " << ec;
            return needs_read;
          }
          case SSL_ERROR_SSL:
            BOOST_LOG_TRIVIAL(error) << "SSL_read: protocol error";
            ERR_print_errors_fp(stderr);
            // TODO better error messages
            return_error(svc, ENOTRECOVERABLE);
            return fault;
          default:
            // TODO better error messages
            BOOST_LOG_TRIVIAL(error) << "SSL_read: unknown error: " << err;
            ERR_print_errors_fp(stderr);
            return_error(svc, ENOTRECOVERABLE);
            return fault;
          }
        }
      }

      virtual void cancel(boost::asio::io_service &svc) {
        return_error(svc, ECANCELED);
      }

    private:
      void return_error(boost::asio::io_service &svc, int errno_) {
        svc.post(boost::bind<void>(m_completion, boost::system::error_code(errno_, boost::system::generic_category()), 0));
      }

      std::uint8_t *m_buffer;
      std::size_t m_buffer_size;
      Completion m_completion;
    };

    template<typename Completion>
    class SSLWriteOp : public DTLSChannelOp {
    public:
      SSLWriteOp(const boost::asio::const_buffer &buf,
                 const Completion &completion)
        : m_buffer(boost::asio::buffer_cast<const std::uint8_t *>(buf)),
          m_buffer_size(boost::asio::buffer_size(buf)),
          m_completion(completion) {
        set_wait(false, true);
      }

      ~SSLWriteOp() {
      }

      virtual Priority priority() const { return priority_application_write; }

      virtual Result operator() (SSL *ssl, boost::asio::io_service &svc) {
        //BOOST_LOG_TRIVIAL(debug) << "SSL_write: starting";
        int r (SSL_write(ssl, m_buffer, m_buffer_size));
        if ( r > 0 ) {
          //BOOST_LOG_TRIVIAL(debug) << "SSL_write: completes";
          svc.post(boost::bind<void>(m_completion, boost::system::error_code(), (std::size_t) r));
          return completes;
        } else {
          int err(SSL_get_error(ssl, r));
          //BOOST_LOG_TRIVIAL(debug) << "SSL_write: completes (waiting)";
          switch ( err ) {
          case SSL_ERROR_WANT_READ: return needs_read;
          case SSL_ERROR_WANT_WRITE: return needs_write;
          case SSL_ERROR_SYSCALL: {
            //auto ec(errno);
            //BOOST_LOG_TRIVIAL(error) << "SSL_write: syscall failed: " << ec;
            return needs_read;
          }
          case SSL_ERROR_SSL:
            BOOST_LOG_TRIVIAL(error) << "SSL_write: protocol error";
            ERR_print_errors_fp(stderr);
            return_error(svc, ENOTRECOVERABLE);
            return fault;
          default:
            BOOST_LOG_TRIVIAL(error) << "SSL_write: unknown error";
            return_error(svc, ENOTRECOVERABLE);
            return fault;
          }
        }
      }

      virtual void cancel(boost::asio::io_service &svc) {
        return_error(svc, ECANCELED);
      }

    private:
      void return_error(boost::asio::io_service &svc, int errno_) {
        svc.post(boost::bind<void>(m_completion, boost::system::error_code(errno_, boost::system::generic_category()), 0));
      }

      const std::uint8_t *m_buffer;
      std::size_t m_buffer_size;
      Completion m_completion;
    };

    class DTLSChannel {
    public:
      using executor_type = boost::asio::io_service;

      DTLSChannel(const DTLSContext &ctxt, std::function<void()> on_send);
      ~DTLSChannel();

      inline const DTLSContext &dtls_context() const { return m_dtls_context; }

      inline boost::asio::io_service &service() { return m_dtls_context.service(); }
      inline executor_type &get_executor() { return m_dtls_context.service(); }

      bool push_datagram(const boost::asio::const_buffer &b);

      bool has_outgoing_datagram();
      boost::asio::const_buffer next_outgoing_datagram();

      /** Cancel all operations in queue */
      void cancel();

      static void setup_ssl();

      template<typename Completion>
      void async_receive(const boost::asio::mutable_buffer &buf,
                         const Completion &completion) {
        submit_op< SSLReadOp<Completion> >(buf, completion);
      }

      template<typename Completion>
      void async_receive_from(const boost::asio::mutable_buffer &buf,
                              boost::asio::ip::address &source,
                              const Completion &completion) {
        source = boost::asio::ip::address();
        async_receive(buf, completion);
      }

      template<typename Completion>
      void async_send(const boost::asio::const_buffer &buf,
                      const Completion &completion) {
        submit_op< SSLWriteOp<Completion> >(buf, completion);

        perform_write_op();
        m_on_send();
      }

    protected:

      void swap(DTLSChannel &c) noexcept;

      template<typename T, typename... Args>
      void submit_op(Args... args) {
        boost::unique_lock l(m_conn_mutex);
        bool do_perform(m_ops_queue.empty());

        m_ops_queue.push(std::make_unique<T>(args...));
        BOOST_LOG_TRIVIAL(debug) << "We now have " << m_ops_queue.size() << " operations";
        if ( do_perform ) // If this is the only operation, then try to run it
          perform_op();
      }

    private:
      void perform_write_op();
      void perform_read_op();
      void perform_op();

      const DTLSContext &m_dtls_context;
      std::function<void()> m_on_send;

      boost::mutex m_conn_mutex;
      using OpsQueue =
        boost::heap::priority_queue< std::shared_ptr<DTLSChannelOp>,
                                     boost::heap::compare< DTLSChannelOp::ComparePriority >,
                                     boost::heap::stable<true> >;

      OpsQueue m_ops_queue;

      SSL *m_ssl_conn;
      BIO *m_io;

      static constexpr std::size_t BUFFER_SIZE = 8192;
      std::array<char, BUFFER_SIZE> m_buffer;

      static int m_ssl_data_index;

      friend class DTLSHelpers;
    };

    class DTLSServer : public DTLSChannel {
    public:
      DTLSServer(const DTLSContext &ctxt, std::function<void()> on_send);
      ~DTLSServer();

      void swap(DTLSServer &s) noexcept;

    private:
      void start_listen();
      void listen_completes(boost::system::error_code ec);
      void connection_ready(boost::system::error_code ec);

      BIO_ADDR *m_bio_addr;

      char m_test_buffer[1024];
    };


    // // TODO this should be push-based, not pull-based
    // template<typename Socket>
    // class DTLSChannel {
    // public:
    //   DTLSChannel(const boost::asio::ip::udp::endpoint &remote,
    //               const X509Certificate &c, Socket &&s)
    //     : m_socket_strand(s.service()), m_socket(std::move(s)),
    //       m_certificate(c), m_ssl_ctx(NULL), m_ssl_conn(NULL),
    //       m_data_source_bio(NULL), m_remote(remote) {

    //     setup();

    //   }
    //   ~DTLSChannel();

    //   bool valid() {
    //     return m_ssl_ctx && m_ssl_conn && m_data_source_bio;
    //   }

    //   template<typename CompletionHandler>
    //   void async_handshake(CompletionHandler completion) {
    //     m_socket_strand.dispatch(boost::bind(&DTLSChannel<Socket>::do_handshake<CompletionHandler>, this, std::move(completion)));
    //   }

    // private:
    //   void setup() {
    //     m_ssl_ctx = SSL_CTX_new(DTLS_server_method());
    //     if ( !m_ssl_ctx ) {
    //       BOOST_LOG(error) << "Aborting DTLS setup because we couldn't create SSL context";
    //       return;
    //     }

    //     m_ssl_conn = SSL_new(m_ssl_ctx);
    //     if ( !m_ssl_conn ) {
    //       BOOST_LOG(error) << "Aborting DTLS setup because we couldn't create SSL object";
    //       return;
    //     }

    //     BIO *recvd, *to_send;
    //     if ( !BIO_make_bio_pair(m_incoming_bio, sink) ) {
    //       BOOST_LOG(error) << "Aborting DTLS setup because we couldn't make the BIO pairs";
    //       return;
    //     }

    //     if ( !BIO_make_bio_pair(to_send, m_outgoing_bio) ) {
    //       BOOST_LOG(error) << "Aborting DTLS setup because we couldn't make the BIO pairs";
    //       return;
    //     }

    //     SSL_set_bio(m_ssl_conn, recvd, to_send);
    //   }

    //   template<typename CompletionHandler>
    //   void do_handshake(CompletionHandler completion) {
    //     // Attempt to perform SSL_accept. If it returns an error,
    //     // check if we want to read more stuff

    //     int err = SSL_accept(m_ssl_conn);
    //     if ( err ) {
    //       m_socket.service().post(boost::bind(completion, boost::system::error_code()));
    //     } else {
    //       int err_kind = SSL_get_error(m_ssl_conn, err);
    //       switch ( err_kind ) {
    //       case SSL_ERROR_WANT_READ:
    //         // We need to wait for more data to appear on our socket
    //         async_wait_read([completion, this] (boost::system::error_code ec) {
    //             if ( ec )
    //               completion(ec);
    //             else
    //               m_socket_strand.dispatch(boost::bind(&DTLSChannel<Socket>::do_handshake<CompletionHandler>, this, completion));
    //           });
    //         break;
    //       case SSL_ERROR_WANT_WRITE:
    //         // We have always flushed out buffers, so if this is true,
    //         // we want to write more than 17kb in a single
    //         // datagram. Fail
    //         m_socket.service().post(boost::bind(completion, dtls_out_of_mem));
    //         break;
    //       case SSL_ERROR_ZERO_RETURN:
    //         m_socket.service().post(boost::bind(completion, dtls_connection_closed));
    //         break;
    //       case SSL_ERROR_SYSCALL:
    //         m_socket.service().post(boost::bind(completion, use_errno));
    //         break;
    //       case SSL_ERROR_SSL:
    //         // Get error from error queue
    //         m_socket.service().post(boost::bind(completion, dtls_error_from_queue()));
    //         break;
    //       case SSL_ERROR_WANT_ASYNC:
    //       case SSL_ERROR_WANT_ASYNC_JOB:
    //       case SSL_ERROR_WANT_X509_LOOKUP:
    //       case SSL_ERROR_WANT_CONNECT:
    //       case SSL_ERROR_WANT_ACCEPT:
    //       case SSL_ERROR_NONE:
    //       default:
    //         m_socket.service().post(boost::bind(completion, dtls_unknown));
    //         break;
    //       }
    //     }
    //   }

    //   template<typename Completion>
    //   void async_wait_read(Completion completion) {
    //     async_flush_write_queue([completion{std::move(completion)}, this] () {
    //         m_socket_strand.post([completion{std::move(completion)}, this] () {
    //             m_socket.async_recv_some
    //               (m_buffer, m_remote,
    //                [completion{std::move(completion)}, this] () {
    //                 if ( m_remote != remote ) goto restart_read;
    //                 else {
    //                   BIO_write_ex(buffer....);
    //                   // If fail, send oom exception

    //                   // Otherwise call completion handler
    //                   completion(...);
    //                 }
    //               });
    //           });
    //       });
    //   }

    //   boost::asio::strand m_socket_strand;
    //   Socket m_socket;
    //   const X509Certificate &m_certificate;

    //   SSL_CTX *m_ssl_ctx;
    //   SSL *m_ssl_conn;
    //   BIO *m_incoming_bio, *m_outgoing_bio;

    //   boost::asio::ip::udp::endpoint m_remote;
    // };
  }
}

namespace std {
  inline void swap(stork::peer::DTLSServer &c, stork::peer::DTLSServer &b) noexcept {
    c.swap(b);
  }
}

#endif
