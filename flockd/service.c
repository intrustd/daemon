#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/err.h>

#include "service.h"
#include "state.h"
#include "event.h"
#include "appliance.h"
#include "client.h"

#define DEFAULT_CLIENT_TIMEOUT 5000 // Keep DTLS contexts around for 30 seconds

#define OP_FLOCKSERVICE_SOCKET EVT_CTL_CUSTOM
#define OP_FSCS_EXPIRE         EVT_CTL_CUSTOM

// Data structures
struct flocksvcclientstate {
  struct flockclientstate fscs_base_st; // This is the basic state that all clients have

  struct flockservice *fscs_svc;

  struct sockaddr fscs_addr;
  UT_hash_handle  fscs_hash_ent;

  struct timersub fscs_client_timeout;

  // Each client has a DTLS context that we use for communication
  SSL *fscs_dtls;

  // Client state
  uint32_t fscs_flags;

  pthread_mutex_t fscs_outgoing_mutex;
  struct BIO_static fscs_outgoing;
  char fscs_outgoing_buf[PKT_BUF_SZ];
  struct flocksvcclientstate *fscs_next_outgoing;

  // A client may be an appliance
  struct applianceinfo fscs_appliance;
};

#define FSCS_IS_APPLIANCE               0x00000001
#define FSCS_OUTGOING_MUTEX_INITIALIZED 0x80000000

#define FSCS_HAS_OUTGOING(fscs) ((fscs)->fscs_outgoing.bs_ptr > 0)
#define FSCS_CAN_SEND_MORE(fscs) !(FSCS_HAS_OUTGOING(fscs))

#define FSCS_REF(fscs) FLOCKCLIENT_REF(&(fscs)->fscs_base_st);
#define FSCS_UNREF(fscs) FLOCKCLIENT_UNREF(&(fscs)->fscs_base_st);

static void flockservice_fn(struct eventloop *el, int op, void *arg);

// client state functions
static void fscs_ensure_enqueued_out(struct flockservice *svc, struct flocksvcclientstate *st);
static int fscs_release(struct flocksvcclientstate *st);

static void fscs_fn(struct eventloop *el, int op, void *arg) {
  struct qdevent *tmr_evt = (struct tmrevent *)arg;
  struct flocksvcclientstate *st = STRUCT_FROM_BASE(struct flocksvcclientstate, fscs_client_timeout, tmr_evt->qde_timersub);

  switch ( op ) {
  case OP_FSCS_EXPIRE:
    fprintf(stderr, "The client state is expiring\n");
    FSCS_UNREF(st);
    break;
  default:
    break;
  }
}

static void fscs_client_fn(struct flockservice *svc, struct flockclientstate *st_base, int op, void *arg) {
  struct flocksvcclientstate *st = STRUCT_FROM_BASE(struct flocksvcclientstate, fscs_base_st, st_base);
  char pkt_buf[PKT_BUF_SZ];
  int err;

  fprintf(stderr, "fscs_client_fn: %d\n", op);

  switch ( op ) {
  case FSC_RECEIVE_PKT:
    BIO_reset(SSL_get_rbio(st->fscs_dtls));
    BIO_reset(SSL_get_wbio(st->fscs_dtls));
    // Handle receiving this packet
    err = SSL_read(st->fscs_dtls, pkt_buf, sizeof(pkt_buf));
    if ( err <= 0 ) {
      err = SSL_get_error(st->fscs_dtls, err);
      switch ( err ) {
      case SSL_ERROR_WANT_READ:
        fprintf(stderr, "fscs_client_fn(FSC_RECEIVE_PKT): Incomplete packet\n");
        break;
      case SSL_ERROR_ZERO_RETURN:
      case SSL_ERROR_SSL:
        fprintf(stderr, "fscs_client_fn(FSC_RECEIVE_PKT): SSL_read: protocol error\n");
        ERR_print_errors_fp(stderr);
        break;
      case SSL_ERROR_SYSCALL:
        perror("SSL_read");
        break;
      case SSL_ERROR_WANT_CONNECT:
      case SSL_ERROR_WANT_ACCEPT:
      case SSL_ERROR_WANT_WRITE:
      case SSL_ERROR_NONE:
      default:
        fprintf(stderr, "fscs_client_fn(FSC_RECEIVE_PKT): SSL_get_error: %d\n", err);
        ERR_print_errors_fp(stderr);
        break;
      }
    } else {
      fprintf(stderr, "Received packet of length %d\n", err);
    }

    fprintf(stderr, "Checking outgoing packet %ld\n", st->fscs_outgoing.bs_ptr);

    if ( FSCS_HAS_OUTGOING(st) )
      fscs_ensure_enqueued_out(svc, st);
    break;
  default:
    fprintf(stderr, "fscs_client_fn: Unknown op: %d\n", op);
  }
}

static int fscs_init(struct flocksvcclientstate *st, struct flockservice *svc, SSL *dtls,
                     struct sockaddr *peer, shfreefn freefn) {
  if ( fcs_init(&st->fscs_base_st, fscs_client_fn, freefn) != 0 ) return -1;

  memcpy(&st->fscs_addr, peer, sizeof(st->fscs_addr));

  if ( !SSL_up_ref(dtls) ) goto error;

  if ( pthread_mutex_init(&st->fscs_outgoing_mutex, NULL) != 0 ) goto error;

  st->fscs_svc = svc;
  st->fscs_dtls = dtls;
  st->fscs_flags = FSCS_OUTGOING_MUTEX_INITIALIZED;
  st->fscs_next_outgoing = NULL;

  st->fscs_outgoing.bs_buf = st->fscs_outgoing_buf;
  st->fscs_outgoing.bs_sz = -PKT_BUF_SZ;
  st->fscs_outgoing.bs_ptr = 0;

  timersub_init_from_now(&st->fscs_client_timeout, DEFAULT_CLIENT_TIMEOUT, OP_FSCS_EXPIRE, fscs_fn);

  applianceinfo_clear(&st->fscs_appliance);

  return 0;

 error:
  fscs_release(st);
  return -1;
}

static int fscs_release(struct flocksvcclientstate *st) {
  int ret = 0;

  fsc_release(&st->fscs_base_st);

  pthread_mutex_lock(&st->fscs_outgoing_mutex);

  ret = FSCS_HAS_OUTGOING(st);

  pthread_mutex_unlock(&st->fscs_outgoing_mutex);
  pthread_mutex_destroy(&st->fscs_outgoing_mutex);
  st->fscs_flags &= ~FSCS_OUTGOING_MUTEX_INITIALIZED;

  if ( st->fscs_dtls )
    SSL_free(st->fscs_dtls);

  return ret;
}

static void free_fscs(const struct shared *s) {
  struct flockclientstate *st_base = STRUCT_FROM_BASE(struct flockclientstate, fcs_shared, s);
  struct flocksvcclientstate *st = STRUCT_FROM_BASE(struct flocksvcclientstate, fscs_base_st, st_base);

  fprintf(stderr, "Freeing flock client state\n");

  // Also attempt to remove ourselves from the hash table
  pthread_rwlock_wrlock(&st->fscs_svc->fs_clients_mutex);
  HASH_DELETE(fscs_hash_ent, st->fscs_svc->fs_clients_hash, st);
  pthread_rwlock_unlock(&st->fscs_svc->fs_clients_mutex);

  fscs_release(st);
  free(st);
}

static struct flocksvcclientstate *fscs_alloc(struct flockservice *svc, SSL *dtls, struct sockaddr *peer) {
  struct flocksvcclientstate *st = (struct flocksvcclientstate *) malloc(sizeof(*st));
  if ( !st ) {
    fprintf(stderr, "fscs_alloc: out of memory\n");
    return NULL;
  }

  if ( fscs_init(st, svc, dtls, peer, free_fscs) != 0 ) {
    free(st);
    return NULL;
  }

  return st;
}

static void fscs_subscribe(struct flocksvcclientstate *st, struct eventloop *el) {
  eventloop_subscribe_timer(el, &st->fscs_client_timeout);
}

static void fscs_ensure_enqueued_out(struct flockservice *svc, struct flocksvcclientstate *st) {
  pthread_mutex_lock(&svc->fs_service_mutex);

  if ( !st->fscs_next_outgoing ) {
    FSCS_REF(st);
    st->fscs_next_outgoing = st; // Setting this equal to itself indicates the end

    assert((svc->fs_first_outgoing && svc->fs_last_outgoing) ||
           (!svc->fs_first_outgoing && !svc->fs_last_outgoing));
    if ( svc->fs_last_outgoing ) {
      svc->fs_last_outgoing->fscs_next_outgoing = st;
      svc->fs_last_outgoing = st;
    } else
      svc->fs_first_outgoing = svc->fs_last_outgoing = st;
  }

  pthread_mutex_unlock(&svc->fs_service_mutex);
}

// Object functions
static int flockservice_open_sk(struct flockservice *svc, struct eventloop *el, uint16_t port) {
  struct sockaddr_in ep;
  int err;

  err = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if ( err < 0 ) {
    perror("flockservice_open_sk: socket");
    return -1;
  }

  svc->fs_service_sk = err;
  fdsub_init(&svc->fs_service_sub, el, svc->fs_service_sk, OP_FLOCKSERVICE_SOCKET, flockservice_fn);

  // Bind to the port
  ep.sin_family = AF_INET;
  ep.sin_addr.s_addr = INADDR_ANY;
  ep.sin_port = htons(port);

  err = bind(svc->fs_service_sk, (struct sockaddr *) &ep, sizeof(ep));
  if ( err < 0 ) {
    perror("flockservice_open_sk: bind");
    goto error;
  }

  // Set non-blocking
  if ( set_socket_nonblocking(svc->fs_service_sk) != 0 ) {
    fprintf(stderr, "Could not set service socket non-blocking\n");
    goto error;
  }

  return 0;

 error:
  close(svc->fs_service_sk);
  svc->fs_service_sk = 0;
  return -1;

}

static int generate_cookie_cb(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
  static const char simple_cookie[] = "Cookie"; // TODO generate
  memcpy(cookie, simple_cookie, sizeof(simple_cookie));
  *cookie_len = sizeof(simple_cookie);
  return 1;
}

static int verify_cookie_cb(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
  return 1; // TODO verify
}

int flockservice_init(struct flockservice *svc, X509 *cert, EVP_PKEY *pkey, struct eventloop *el, uint16_t port) {
  int err;

  flockservice_clear(svc);

  if ( flockservice_open_sk(svc, el, port) != 0 ) return -1;

  err = pthread_mutex_init(&svc->fs_service_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "flockservice_init: could not create service mutex: %s\n", strerror(err));
    goto error;
  }
  svc->fs_mutexes_initialized |= FS_SERVICE_MUTEX;

  err = pthread_rwlock_init(&svc->fs_clients_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "flockservice_init: could not create client rwlock: %s\n", strerror(err));
    goto error;
  }
  svc->fs_mutexes_initialized |= FS_CLIENTS_MUTEX;

  svc->fs_ssl_ctx = SSL_CTX_new(DTLS_server_method());
  if ( !svc->fs_ssl_ctx ) {
    fprintf(stderr, "flockservice_init: SSL_CTX_new failed\n");
    goto openssl_error;
  }

  svc->fs_incoming_addr = BIO_ADDR_new();
  if ( !svc->fs_incoming_addr ) {
    fprintf(stderr, "flockservice_init: BIO_addr_new() failed\n");
    goto openssl_error;
  }

  err = SSL_CTX_set_cipher_list(svc->fs_ssl_ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
  if ( err != 1 ) {
    fprintf(stderr, "flockservice_init: Could not add SSL ciphers\n");
    goto openssl_error;
  }

  SSL_CTX_set_verify(svc->fs_ssl_ctx, SSL_VERIFY_NONE, NULL);
  // TODO set verify callback

  err = SSL_CTX_use_certificate(svc->fs_ssl_ctx, cert);
  if ( err != 1 ) {
    fprintf(stderr, "flockservice_init: Could not set SSL certificate\n");
    goto openssl_error;
  }

  err = SSL_CTX_use_PrivateKey(svc->fs_ssl_ctx, pkey);
  if ( err != 1 ) {
    fprintf(stderr, "flockservice_init: Could not set SSL private key\n");
    goto openssl_error;
  }

  err = SSL_CTX_check_private_key(svc->fs_ssl_ctx);
  if ( err != 1 ) {
    fprintf(stderr, "flockservice_init: are you sure this private key is for this certificate?\n");
    goto openssl_error;
  }

  SSL_CTX_set_cookie_generate_cb(svc->fs_ssl_ctx,
                                 generate_cookie_cb);
  SSL_CTX_set_cookie_verify_cb(svc->fs_ssl_ctx,
                               verify_cookie_cb);

  return 0;

 openssl_error:
  ERR_print_errors_fp(stderr);
 error:
  flockservice_release(svc);
  return -1;
}

void flockservice_clear(struct flockservice *svc) {
  svc->fs_mutexes_initialized = 0;
  svc->fs_first_outgoing = NULL;
  svc->fs_last_outgoing = NULL;
  svc->fs_service_sk = 0;
  fdsub_clear(&svc->fs_service_sub);

  svc->fs_sk_incoming.bs_buf = svc->fs_incoming_packet;
  svc->fs_sk_incoming.bs_ptr = svc->fs_sk_incoming.bs_sz = 0;
  svc->fs_incoming_addr = NULL;

  svc->fs_clients_hash = NULL;

  svc->fs_ssl_ctx = NULL;
}

void flockservice_release(struct flockservice *svc) {
  struct flocksvcclientstate *st, *i;

  if ( svc->fs_mutexes_initialized & FS_CLIENTS_MUTEX )
    pthread_rwlock_wrlock(&svc->fs_clients_mutex);

  HASH_ITER(fscs_hash_ent, svc->fs_clients_hash, st, i) {
    FSCS_UNREF(st);
  }

  if ( svc->fs_mutexes_initialized & FS_CLIENTS_MUTEX ) {
    pthread_rwlock_unlock(&svc->fs_clients_mutex);
    pthread_rwlock_destroy(&svc->fs_clients_mutex);
    svc->fs_mutexes_initialized &= ~FS_CLIENTS_MUTEX;
  }

  // TODO, for every single client, decrement the reference count

  if ( svc->fs_mutexes_initialized & FS_SERVICE_MUTEX )
    pthread_mutex_lock(&svc->fs_service_mutex);

  if ( svc->fs_service_sk )
    close(svc->fs_service_sk);
  svc->fs_service_sk = 0;

  if ( svc->fs_incoming_addr )
    BIO_ADDR_free(svc->fs_incoming_addr);
  svc->fs_incoming_addr = NULL;

  if ( svc->fs_ssl_ctx ) {
    SSL_CTX_free(svc->fs_ssl_ctx);
    svc->fs_ssl_ctx = NULL;
  }

  if ( svc->fs_mutexes_initialized & FS_SERVICE_MUTEX ) {
    pthread_mutex_unlock(&svc->fs_service_mutex);
    pthread_mutex_destroy(&svc->fs_service_mutex);
    svc->fs_mutexes_initialized &= ~FS_SERVICE_MUTEX;
  }
}

void flockservice_start(struct flockservice *svc, struct eventloop *el) {
  svc->fs_service_sub.fds_subscriptions |= FD_SUB_READ;
  eventloop_subscribe_fd(el, svc->fs_service_sk, &svc->fs_service_sub);
}

// Service

static int receive_next_packet(struct flockservice *st, struct sockaddr *datagram_addr) {
  int err;
  socklen_t addr_sz = sizeof(*datagram_addr);
  char addr_buf[INET6_ADDRSTRLEN];

  err = recvfrom(st->fs_service_sk, st->fs_incoming_packet, sizeof(st->fs_incoming_packet),
                 0, datagram_addr, &addr_sz);
  if ( err < 0 ) {
    perror("next_packet_address: recvmsg");
    return -1;
  } else if ( err == 0 ) {
    fprintf(stderr, "next_packet_address: socket reports that it has shutdown\n");
    return -1;
  }

  BIO_STATIC_SET_READ_SZ(&st->fs_sk_incoming, err);

  fprintf(stderr, "Got packet from address %s:%d\n",
          inet_ntop(datagram_addr->sa_family, SOCKADDR_DATA(datagram_addr),
                    addr_buf, sizeof(addr_buf)),
          ntohs(((struct sockaddr_in *) datagram_addr)->sin_port));

  return 0;
}

static void flock_service_accept(struct flockservice *st, struct eventloop *eventloop, struct sockaddr *peer) {
  int err;
  SSL *ssl = NULL;
  BIO *bio_in = NULL, *bio_out = NULL;
  struct flocksvcclientstate *client_st = NULL;
  struct BIO_static outgoing_bio;
  char pkt_out[PKT_BUF_SZ];

  fprintf(stderr, "flock_service_accept\n");

  ssl = SSL_new(st->fs_ssl_ctx);
  if ( !ssl ) {
    fprintf(stderr, "flock_service_accept: Could not create SSL object\n");
    goto openssl_error;
  }

  bio_in = BIO_new_static(BIO_STATIC_READ, &st->fs_sk_incoming);
  if ( !bio_in ) {
    fprintf(stderr, "flock_service_accept: out of memory\n");
    goto openssl_error;
  }

  outgoing_bio.bs_buf = pkt_out;
  outgoing_bio.bs_sz = sizeof(pkt_out);
  outgoing_bio.bs_ptr = 0;
  bio_out = BIO_new_static(BIO_STATIC_WRITE, &outgoing_bio);
  if ( !bio_out ) {
    fprintf(stderr, "flock_service_accept: out of memory\n");
    goto openssl_error;
  }

  SSL_set_bio(ssl, bio_in, bio_out);
  bio_in = bio_out = NULL;

  BIO_ADDR_clear(st->fs_incoming_addr);
  err = DTLSv1_listen(ssl, st->fs_incoming_addr);
  if ( err < 0 ) {
    err = SSL_get_error(ssl, err);
    switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_ZERO_RETURN:
    case SSL_ERROR_SSL:
      fprintf(stderr, "flock_service_accept: Invalid packet sent to DTLS socket\n");
      goto flush;
    case SSL_ERROR_WANT_CONNECT:
    case SSL_ERROR_WANT_ACCEPT:
      fprintf(stderr, "flock_service_accept: Internal DTLS error\n");
      goto flush;
    case SSL_ERROR_SYSCALL:
      // The special retry is marked if we flushed
      if ( !BIO_should_io_special(SSL_get_wbio(ssl)) )
        perror("flock_service_accept: DTLSv1_listen");
      goto flush;
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_NONE:
    default:
      fprintf(stderr, "flock_service_accept: DTLSv1_listen fails\n");
      goto flush;
    }
  } else if ( err == 0 ) {
    // A non-fatal error means this wrote something out
    fprintf(stderr, "Non-fatal error on socket\n");
    goto flush;
  }
  fprintf(stderr, "DTLSv1Listen suceeds\n");

  err = SSL_accept(ssl);
  fprintf(stderr, "SSL_accept returns\n");
  if ( err <= 0 ) {
    err = SSL_get_error(ssl, err);
    switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_ZERO_RETURN:
    case SSL_ERROR_SSL:
      fprintf(stderr, "flock_service_accept: Invalid packet sent to DTLS socket while accepting\n");
      goto flush;
    case SSL_ERROR_WANT_CONNECT:
    case SSL_ERROR_WANT_ACCEPT:
      fprintf(stderr, "flock_service_accept: Internal DTLS error\n");
      goto flush;
    case SSL_ERROR_SYSCALL:
      // The special retry is marked if we flushed
      if ( !BIO_should_io_special(SSL_get_wbio(ssl)) )
        goto flush;
      else
        perror("flock_service_accept: SSL_accept");
      break;
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_NONE:
    default:
      fprintf(stderr, "flock_service_accept: SSL_accept fails\n");
      goto flush;
    }
  }

  // Otherwise, we have a new connection
  fprintf(stderr, "Accepted new connection\n");

  client_st = fscs_alloc(st, ssl, peer);
  if ( !client_st )
    goto error;

  SSL_free(ssl);

  fscs_subscribe(client_st, eventloop);

  // Reset SSL bio
  BIO_static_set(SSL_get_wbio(ssl), &client_st->fscs_outgoing);

  pthread_rwlock_wrlock(&st->fs_clients_mutex);
  HASH_ADD(fscs_hash_ent, st->fs_clients_hash, fscs_addr, sizeof(struct sockaddr), client_st);
  pthread_rwlock_unlock(&st->fs_clients_mutex);

  // Now attempt to send the packet. This may fail if there's no space
  // in the socket buffer, but this is okay.
 flush:
  if ( BIO_STATIC_WPENDING(&outgoing_bio) ) {
    fprintf(stderr, "Responding to DTLS handshake\n");
    err = sendto(st->fs_service_sk, pkt_out, BIO_STATIC_WPENDING(&outgoing_bio), 0,
                 peer, sizeof(*peer));
    if ( err < 0 && errno != EAGAIN && errno != EWOULDBLOCK ) {
      perror("sendto");
      goto error;
    } else if ( err == 0 ) {
      fprintf(stderr, "Ignoring handshake because we have no space in our send buffer\n");
    }
  }

  return;

 openssl_error:
  ERR_print_errors_fp(stderr);
 error:
  if ( ssl ) SSL_free(ssl);
  if ( bio_in ) BIO_free(bio_in);
  if ( bio_out ) BIO_free(bio_out);
  if ( client_st ) free(client_st);
}

static void flock_service_handle_read(struct flockservice *st, struct eventloop *eventloop) {
  struct sockaddr datagram_addr;
  struct flocksvcclientstate *client = NULL;

  memset(&datagram_addr, 0, sizeof(datagram_addr));

  if( receive_next_packet(st, &datagram_addr) != 0 ) {
    fprintf(stderr, "Could not fetch next datagram\n");
    return;
  }

  // Lookup address in hash table
  HASH_FIND(fscs_hash_ent, st->fs_clients_hash, &datagram_addr, sizeof(datagram_addr), client);
  if ( !client ) {
    fprintf(stderr, "This is a new client\n");

    // Attempt to run SSL_accept on this data gram
    flock_service_accept(st, eventloop, &datagram_addr);
  } else {
    fprintf(stderr, "This is an old client\n");

    // The datagram is delivered if we have space in the outgoing packet queue
    pthread_mutex_lock(&client->fscs_outgoing_mutex);
    if ( FSCS_CAN_SEND_MORE(client) ) {
      // Continue
      client->fscs_base_st.fcs_fn(st, &client->fscs_base_st, FSC_RECEIVE_PKT, NULL);
    } else
      fprintf(stderr, "Ignoring data because there is no space in the outgoing buffer\n");
    pthread_mutex_unlock(&client->fscs_outgoing_mutex);
  }
}

static void flock_service_flush_buffers(struct flockservice *st) {
  int err;
  struct flocksvcclientstate *cli, *old_cli;
  fprintf(stderr, "Flushing buffers\n");

  pthread_mutex_lock(&st->fs_service_mutex);
  for ( cli = st->fs_first_outgoing; cli;
        old_cli = cli, cli = cli->fscs_next_outgoing == cli ? NULL : cli->fscs_next_outgoing, old_cli->fscs_next_outgoing = NULL ) {
    // Attempt to write out the buffer with the DTLS context
    err = sendto(st->fs_service_sk, cli->fscs_outgoing_buf, BIO_STATIC_WPENDING(&cli->fscs_outgoing), 0,
                 (void *) &cli->fscs_addr, sizeof(cli->fscs_addr));
    BIO_STATIC_RESET_WRITE(&cli->fscs_outgoing);
    if ( err < 0 ) {
      if ( errno == EWOULDBLOCK ) break;
      perror("flock_service_flush_buffers: sendto");
    }

    FSCS_UNREF(cli);
  }

  st->fs_first_outgoing = cli;
  if ( !st->fs_first_outgoing )
    st->fs_last_outgoing = NULL;

  pthread_mutex_unlock(&st->fs_service_mutex);
}

static void flock_service_handle_event(struct flockservice *st, struct eventloop *el, struct fdevent *ev) {
  fprintf(stderr, "Flock service got socket event\n");

  if ( FD_WRITE_AVAILABLE(ev) )
    flock_service_flush_buffers(st);

  if ( FD_READ_PENDING(ev) ) { // && BIO_ctrl_wpending(st->fs_service_bio) == 0 ) {
    // Only read data if there is no write pending
    flock_service_handle_read(st, el);
  }

  pthread_mutex_lock(&st->fs_service_mutex);
  if ( st->fs_first_outgoing )
    st->fs_service_sub.fds_subscriptions |= FD_SUB_WRITE | FD_SUB_WRITE_OOB;
  else
    st->fs_service_sub.fds_subscriptions &= ~(FD_SUB_WRITE | FD_SUB_WRITE_OOB);
  pthread_mutex_unlock(&st->fs_service_mutex);

  eventloop_subscribe_fd(el, st->fs_service_sk, &st->fs_service_sub);
}

void flockservice_fn(struct eventloop *el, int op, void *arg) {
  struct fdevent *ev;
  switch ( op ) {
  case OP_FLOCKSERVICE_SOCKET:
    ev = (struct fdevent *) arg;
    if ( IS_FDEVENT(ev) )
      flock_service_handle_event
        (STATE_FROM_FDSUB(struct flockservice, fs_service_sub, ev->fde_sub), el, ev);
    else
      fprintf(stderr, "flockservice_fn: Got event with bad type: %d\n", ev->fde_ev.ev_type);
    break;
  default:
    fprintf(stderr, "flockservice_fn: Unknown op %d\n", op);
  }
}
