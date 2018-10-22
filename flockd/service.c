#include <openssl/err.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>

#include "service.h"
#include "state.h"
#include "event.h"
#include "appliance.h"
#include "client.h"
#include "personas.h"

#define DEFAULT_CLIENT_TIMEOUT 60000 // Keep DTLS contexts around for 30 seconds

#define FLOCK_DTLS_COOKIE_LENGTH 32

#define OP_FLOCKSERVICE_SOCKET EVT_CTL_CUSTOM
#define OP_FSCS_EXPIRE         EVT_CTL_CUSTOM

// Data structures
struct flocksvcclientstate {
  struct flockclientstate fscs_base_st; // This is the basic state that all clients have

  struct flockservice *fscs_svc;

  kite_sock_addr  fscs_addr;
  UT_hash_handle  fscs_hash_ent;

  struct timersub fscs_client_timeout;

  // Each client has a DTLS context that we use for communication
  SSL *fscs_dtls;

  // Client state
  pthread_mutex_t fscs_state_mutex;
  uint32_t fscs_flags;

  pthread_mutex_t fscs_outgoing_mutex;
  struct BIO_static fscs_outgoing;
  char fscs_outgoing_buf[PKT_BUF_SZ];
  struct flocksvcclientstate *fscs_next_outgoing;

  // Packets that need to be sent to this client
  DLIST_HEAD(struct fcspktwriter) fscs_outgoing_packets;

  // A client may be an appliance
  struct applianceinfo fscs_appliance;
};

#define FSCS_IS_APPLIANCE               0x00000001
#define FSCS_OUTGOING_MUTEX_INITIALIZED 0x80000000
#define FSCS_STATE_MUTEX_INITIALIZED    0x40000000

#define FSCS_HAS_OUTGOING(fscs) ((fscs)->fscs_outgoing.bs_ptr > 0)
#define FSCS_HAS_PENDING_WRITES(fscs)  (FSCS_HAS_OUTGOING(fscs) || !DLIST_EMPTY(&fscs->fscs_outgoing_packets))
#define FSCS_CAN_SEND_MORE(fscs) !(FSCS_HAS_OUTGOING(fscs))

#define FSCS_REF(fscs) FLOCKCLIENT_REF(&(fscs)->fscs_base_st)
#define FSCS_UNREF(fscs) FLOCKCLIENT_UNREF(&(fscs)->fscs_base_st)

#define FSCS_FROM_APPINFO(info) STRUCT_FROM_BASE(struct flocksvcclientstate, fscs_appliance, info)

static void flockservice_fn(struct eventloop *el, int op, void *arg);
static int flockservice_handle_startconn_response(struct flockservice *svc,
                                                  const struct stunmsg *msg, int buf_sz);
static int flockservice_handle_offer_response(struct flockservice *svc,
                                              const struct stunmsg *msg, int buf_sz);

// client state functions
// Ensure that the client is in the outgoing queue. fscs_outgoing_mutex must not be held
static void fscs_ensure_enqueued_out(struct flockservice *svc, struct flocksvcclientstate *st);
static int fscs_release(struct flocksvcclientstate *st);
static void fscs_touch_timeout(struct flocksvcclientstate *st, struct eventloop *el);

static void fscs_handle_stun_request(struct flocksvcclientstate *st, struct flockservice *svc,
                                     const char *buf, int buf_sz);
static void fscs_write_response(struct flocksvcclientstate *st, const char *rsp, size_t sz);
static void fscs_free_appliance(const struct shared *sh, int level);

void ai_do_queue(struct fcspktwriter *pw) {
  struct applianceinfo *ai = (struct applianceinfo *) pw->fcspw_queue_info;
  struct flocksvcclientstate *st = FSCS_FROM_APPINFO(ai);

  SAFE_MUTEX_LOCK(&st->fscs_outgoing_mutex);
  fprintf(stderr, "fscs_appliancefn: adding packet to queue\n");
  // We do not release the reference we have to conn. This is released in
  // flock_service_flush_buffers
  if ( !DLIST_ENTRY_IN_LIST(&st->fscs_outgoing_packets, fcspw_dl, pw) ) {
    if ( pw->fcspw_sh )
      SHARED_REF(pw->fcspw_sh);
    DLIST_INSERT(&st->fscs_outgoing_packets, fcspw_dl, pw);
  }
  pthread_mutex_unlock(&st->fscs_outgoing_mutex);

  fscs_ensure_enqueued_out(st->fscs_svc, st);
  eventloop_subscribe_fd(&(FLOCKSTATE_FROM_SERVICE(st->fscs_svc)->fs_eventloop),
                         st->fscs_svc->fs_service_sk, FD_SUB_WRITE,
                         &st->fscs_svc->fs_service_sub);

  if ( pw->fcspw_sh )
    SHARED_UNREF(pw->fcspw_sh);
}

static int fscs_appliancefn(struct applianceinfo *info, int op, void *arg) {
  struct flocksvcclientstate *st;
  struct fcspktwriter *pw;
  struct aireconcile *air;
  X509 **certp;

  st = FSCS_FROM_APPINFO(info);

  switch ( op ) {
  case AI_OP_GET_PEER_ADDR:
    memcpy(arg, &st->fscs_addr, sizeof(st->fscs_addr));
    return 0;
  case AI_OP_RECONCILE: // TODO reconciliation
    air = (struct aireconcile *) arg;
    if ( strcmp(air->air_old->ai_name,
                air->air_new->ai_name) == 0 ) {
      int ret = -1;

      X509 *old_cert = applianceinfo_get_peer_certificate(air->air_old);
      X509 *new_cert = applianceinfo_get_peer_certificate(air->air_new);

      if ( old_cert && new_cert ) {
        // Check public keys the same
        EVP_PKEY *old_pkey = X509_get_pubkey(old_cert);
        EVP_PKEY *new_pkey = X509_get_pubkey(new_cert);
        fprintf(stderr, "Get old pkey %p, new pkey %p\n", old_pkey, new_pkey);
        if ( old_pkey && new_pkey ) {
          if ( EVP_PKEY_cmp(old_pkey, new_pkey) == 1 )
            ret = 0;
          else
            ret = -1;
        } else
          ret = -2;

        if ( old_pkey ) EVP_PKEY_free(old_pkey);
        if ( new_pkey ) EVP_PKEY_free(new_pkey);
      } else
        ret = -2;

      if ( old_cert ) X509_free(old_cert);
      if ( new_cert ) X509_free(new_cert);

      return ret;
    } else
      return -1;
    break;

  case AI_OP_GET_CERTIFICATE:
    certp = (X509 **) arg;
    *certp = SSL_get_peer_certificate(st->fscs_dtls);
    return 0;

  case AI_OP_SEND_PACKET:
    pw = (struct fcspktwriter *) arg;
    if ( pw->fcspw_sh )
      SHARED_REF(pw->fcspw_sh);

    fprintf(stderr, "fscs_appliancefn: sending packet\n");
    pw->fcspw_do_queue = ai_do_queue;
    pw->fcspw_queue_info = info;
    if ( !eventloop_queue(&(FLOCKSTATE_FROM_SERVICE(st->fscs_svc)->fs_eventloop),
                          &pw->fcspw_queue) ) {
      fprintf(stderr, "fscs_appliancefn: could not queue packet\n");
      if ( pw->fcspw_sh )
        SHARED_UNREF(pw->fcspw_sh);
    }
    return 0;
  default:
    fprintf(stderr, "fscs_appliancefn: got unhandled op %d\n", op);
    return -2;
  }
}

static void fscs_free_appliance(const struct shared *sh, int level) {
  // The appliance is no longer being used by the run-time
  struct applianceinfo *ai = APPLIANCEINFO_FROM_SHARED(sh);
  struct flocksvcclientstate *st = STRUCT_FROM_BASE(struct flocksvcclientstate, fscs_appliance, ai);

  if ( level != SHFREE_NO_MORE_REFS ) return;

  if( pthread_mutex_lock(&st->fscs_state_mutex) == 0 ) {
    st->fscs_flags &= ~FSCS_IS_APPLIANCE;
    pthread_mutex_unlock(&st->fscs_state_mutex);

    // This is in response to the state acquisition in fscs_handle_stun_request
    FSCS_UNREF(st);
  } else
    fprintf(stderr, "fscs_free_appliance: could not free\n");

  if ( pthread_mutex_lock(&ai->ai_mutex) == 0 ) {
    if ( ai->ai_flags & AI_FLAG_ACTIVE )
      flockservice_remove_appliance(st->fscs_svc, ai, FLOCKSERVICE_REMOVE_REASON_APPLIANCE_EXPIRED);
    ai->ai_flags &= ~AI_FLAG_ACTIVE;
    pthread_mutex_unlock(&ai->ai_mutex);
  } else
    fprintf(stderr, "fscs_free_appliance: could not lock appliance\n");
}

static void fscs_fn(struct eventloop *el, int op, void *arg) {
  struct qdevent *tmr_evt = (struct qdevent *)arg;
  struct flocksvcclientstate *st = STRUCT_FROM_BASE(struct flocksvcclientstate, fscs_client_timeout, tmr_evt->qde_timersub);
  int is_appliance;

  switch ( op ) {
  case OP_FSCS_EXPIRE:
    FSCS_REF(st);
    fprintf(stderr, "The client state is expiring\n");

    if ( pthread_mutex_lock(&st->fscs_state_mutex) == 0 ) {
      is_appliance = st->fscs_flags & FSCS_IS_APPLIANCE;
      pthread_mutex_unlock(&st->fscs_state_mutex);
    } else
      is_appliance = 0;

    if ( is_appliance ) {
      AI_UNREF(&st->fscs_appliance);
    }

    FSCS_UNREF(st);
    FSCS_UNREF(st);
    break;
  default:
    break;
  }
}

static void fscs_client_fn(struct flockservice *svc, struct flockclientstate *st_base, int op, void *arg) {
  struct flocksvcclientstate *st = STRUCT_FROM_BASE(struct flocksvcclientstate, fscs_base_st, st_base);
  struct flockstate *flockst = FLOCKSTATE_FROM_SERVICE(svc);
  char pkt_buf[PKT_BUF_SZ];
  int err;


  switch ( op ) {
  case FSC_RECEIVE_PKT:
    // Since we got an event, we retouch the client timeout
    fscs_touch_timeout(st, &flockst->fs_eventloop);

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
      fscs_handle_stun_request(st, svc, pkt_buf, err);
    }

    if ( FSCS_HAS_PENDING_WRITES(st) )
      fscs_ensure_enqueued_out(svc, st);
    break;
  default:
    fprintf(stderr, "fscs_client_fn: Unknown op: %d\n", op);
  }
}

static int fscs_init(struct flocksvcclientstate *st, struct flockservice *svc, SSL *dtls,
                     kite_sock_addr *peer, shfreefn freefn) {
  if ( fcs_init(&st->fscs_base_st, fscs_client_fn, freefn) != 0 ) return -1;

  memset(&st->fscs_addr, 0, sizeof(st->fscs_addr));
  memcpy(&st->fscs_addr, peer, sizeof(st->fscs_addr));

  if ( !SSL_up_ref(dtls) ) goto error;

  st->fscs_flags = 0;
  if ( pthread_mutex_init(&st->fscs_outgoing_mutex, NULL) != 0 ) goto error;
  st->fscs_flags |= FSCS_OUTGOING_MUTEX_INITIALIZED;
  if ( pthread_mutex_init(&st->fscs_state_mutex, NULL) != 0 ) goto error;
  st->fscs_flags |= FSCS_STATE_MUTEX_INITIALIZED;

  st->fscs_svc = svc;
  st->fscs_dtls = dtls;
  st->fscs_next_outgoing = NULL;

  st->fscs_outgoing.bs_buf = st->fscs_outgoing_buf;
  st->fscs_outgoing.bs_sz = -PKT_BUF_SZ;
  st->fscs_outgoing.bs_ptr = 0;

  DLIST_INIT(&st->fscs_outgoing_packets);

  timersub_init_from_now(&st->fscs_client_timeout, DEFAULT_CLIENT_TIMEOUT, OP_FSCS_EXPIRE, fscs_fn);

  if ( applianceinfo_init(&st->fscs_appliance, fscs_free_appliance) < 0 )
    goto error;

  st->fscs_appliance.ai_shared.sh_refcnt = 0;

  st->fscs_appliance.ai_appliance_fn = fscs_appliancefn;
  st->fscs_appliance.ai_flags |= AI_FLAG_SECURE;

  return 0;

 error:
  fscs_release(st);
  return -1;
}

static int fscs_release(struct flocksvcclientstate *st) {
  int ret = 0;
  struct fcspktwriter *pkt, *tmppkt;

  fsc_release(&st->fscs_base_st);

  pthread_mutex_lock(&st->fscs_outgoing_mutex);

  ret = FSCS_HAS_OUTGOING(st);

  pthread_mutex_unlock(&st->fscs_outgoing_mutex);
  pthread_mutex_destroy(&st->fscs_outgoing_mutex);
  st->fscs_flags &= ~FSCS_OUTGOING_MUTEX_INITIALIZED;

  DLIST_ITER(&st->fscs_outgoing_packets, fcspw_dl, pkt, tmppkt) {
    if ( pkt->fcspw_sh )
      SHARED_UNREF(pkt->fcspw_sh);
  }

  applianceinfo_release(&st->fscs_appliance);

  if ( st->fscs_dtls )
    SSL_free(st->fscs_dtls);

  return ret;
}

static void free_fscs(const struct shared *s, int level) {
  struct flockclientstate *st_base = STRUCT_FROM_BASE(struct flockclientstate, fcs_shared, s);
  struct flocksvcclientstate *st = STRUCT_FROM_BASE(struct flocksvcclientstate, fscs_base_st, st_base);

  if ( level != SHFREE_NO_MORE_REFS ) return;

  fprintf(stderr, "Freeing flock client state\n");

  // Also attempt to remove ourselves from the hash table
  SAFE_RWLOCK_WRLOCK(&st->fscs_svc->fs_clients_mutex);
  HASH_DELETE(fscs_hash_ent, st->fscs_svc->fs_clients_hash, st);
  pthread_rwlock_unlock(&st->fscs_svc->fs_clients_mutex);

  AI_UNREF(&st->fscs_appliance);

  fscs_release(st);
  free(st);
}

static struct flocksvcclientstate *fscs_alloc(struct flockservice *svc, SSL *dtls,
                                              kite_sock_addr *peer) {
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

static void fscs_touch_timeout(struct flocksvcclientstate *st, struct eventloop *el) {
  eventloop_cancel_timer(el, &st->fscs_client_timeout);
  timersub_set_from_now(&st->fscs_client_timeout, DEFAULT_CLIENT_TIMEOUT);
  eventloop_subscribe_timer(el, &st->fscs_client_timeout);
}

static void fscs_ensure_enqueued_out(struct flockservice *svc, struct flocksvcclientstate *st) {
  pthread_mutex_lock(&svc->fs_service_mutex);
  pthread_mutex_lock(&st->fscs_outgoing_mutex);

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

  pthread_mutex_unlock(&st->fscs_outgoing_mutex);
  pthread_mutex_unlock(&svc->fs_service_mutex);
}

static void fscs_handle_stun_request(struct flocksvcclientstate *st, struct flockservice *svc,
                                     const char *buf, int buf_sz) {
  struct applianceinfo *app;
  const struct stunmsg *msg = (const struct stunmsg *)buf;
  struct stunvalidation v;
  int err = 0, reg_err;
  uint16_t unknown_attrs[16];
  char response_buf[MAX_STUN_MSG_SIZE];
  size_t response_sz = sizeof(response_buf);

  v.sv_flags      = STUN_NEED_FINGERPRINT;
  v.sv_user_cb    = NULL;
  v.sv_unknown_cb = STUN_ACCEPT_UNKNOWN;
  v.sv_user_data  = st;
  v.sv_unknown_attrs = unknown_attrs;
  v.sv_unknown_attrs_sz = sizeof(unknown_attrs) / sizeof(unknown_attrs[0]);

  err = stun_validate(buf, buf_sz, &v);
  if ( err < 0 || err == STUN_SUCCESS ) { // Negative error codes are responses that contained an error
    fprintf(stderr, "Got stun request\n");

    switch ( STUN_REQUEST_TYPE(msg) ) {
    case STUN_BINDING:
      fprintf(stderr, "TODO binding requests\n");
      break;
    case STUN_KITE_STARTCONN:
      if ( STUN_MESSAGE_TYPE(msg) & STUN_RESPONSE ) {
        err = 0;
        reg_err = flockservice_handle_startconn_response(svc, msg, buf_sz);
        if ( reg_err < 0 ) {
          fprintf(stderr, "Error while processing startconn response\n");
        }
      } else
        err = STUN_BAD_REQUEST;
      break;
    case STUN_KITE_SENDOFFER:
      fprintf(stderr, "Stun kite sendoffer\n");
      if ( STUN_MESSAGE_TYPE(msg) & STUN_RESPONSE ) {
        err = 0;
        reg_err = flockservice_handle_offer_response(svc, msg, buf_sz);
        if ( reg_err < 0 ) {
          fprintf(stderr, "Error while processing offer request\n");
        }
      } else
        err = STUN_BAD_REQUEST;
      break;
    case STUN_KITE_GET_PERSONAS:
      // This is sent to the appliance
      if ( STUN_MESSAGE_TYPE(msg) & STUN_RESPONSE ) {
        err = 0;
        SAFE_MUTEX_LOCK(&st->fscs_state_mutex);
        if ( st->fscs_flags & FSCS_IS_APPLIANCE ) {
          AI_REF(&st->fscs_appliance);
          app = &st->fscs_appliance;
          pthread_mutex_unlock(&st->fscs_state_mutex);
          // If we are an appliance, sen
          reg_err = applianceinfo_receive_persona_response(app, msg, buf_sz);
          if ( reg_err < 0 ) {
            fprintf(stderr, "Could not process persona response\n");
          }
          AI_UNREF(app);
        } else
          pthread_mutex_unlock(&st->fscs_state_mutex);
      } else
        err = STUN_BAD_REQUEST;
      break;
    case STUN_KITE_REGISTRATION:
      // The appliance gets its own reference to our state.
      // This is dereferenced in fscs_free_appliance
      //
      // The reference is released if there is an error or we
      // succeeded, but the state was already an appliance
      if ( err != STUN_SUCCESS ) break;
      FSCS_REF(st);
      reg_err = flockservice_handle_appliance_registration(svc, &st->fscs_appliance, msg, buf_sz,
                                                           response_buf, &response_sz);
      if ( reg_err >= 0 ) {
        SAFE_MUTEX_LOCK(&st->fscs_state_mutex);
        if ( (st->fscs_flags & FSCS_IS_APPLIANCE) != 0 ) {
          FSCS_UNREF(st);
        }
        st->fscs_flags |= FSCS_IS_APPLIANCE;
        pthread_mutex_unlock(&st->fscs_state_mutex);
      } else
        FSCS_UNREF(st);

      if ( reg_err == 0 ) {
        // Attempt to write the response buffer
        fscs_write_response(st, response_buf, response_sz);
      } else if ( reg_err > 0 ) {
        fprintf(stderr, "Could register application\n");
      } else if ( reg_err < 0 ) {
        fprintf(stderr, "There was an error while registering the application\n");
        err = -reg_err;
      }
      break;
    default:
      err = STUN_BAD_REQUEST;
    }
  }

  if ( err == STUN_NOT_STUN ) {
    fprintf(stderr, "ignoring packet because it is not a STUN request\n");
  } else if ( err != STUN_SUCCESS ) {
    fprintf(stderr, "error while parsing STUN request: %s\n", stun_strerror(err));

    // TODO Respond with error now
  }
}

static void fscs_write_response(struct flocksvcclientstate *st, const char *rsp, size_t sz) {
  int err;

  pthread_mutex_lock(&st->fscs_outgoing_mutex);
  fprintf(stderr, "fscs_write_response: response size is %ld\n", sz);
  err = SSL_write(st->fscs_dtls, rsp, sz);
  if ( err <= 0 ) {
    err = SSL_get_error(st->fscs_dtls, err);
    switch ( err ) {
    case SSL_ERROR_WANT_WRITE:
      fprintf(stderr, "fscs_write_response: buffer overflow\n");
      BIO_STATIC_RESET_WRITE(&st->fscs_outgoing);
      break;
    case SSL_ERROR_WANT_READ:
      fprintf(stderr, "fscs_write_response: SSL_ERROR_WANT_READ\n");
      BIO_STATIC_RESET_WRITE(&st->fscs_outgoing);
      break;
    case SSL_ERROR_ZERO_RETURN:
      fprintf(stderr, "fscs_write_response: SSL protocol error\n");
      ERR_print_errors_fp(stderr);
      BIO_STATIC_RESET_WRITE(&st->fscs_outgoing);
      break;
    case SSL_ERROR_SYSCALL:
      if ( BIO_should_io_special(SSL_get_wbio(st->fscs_dtls)) ) {
        fprintf(stderr, "The write BIO was flushed\n");
      } else {
        perror("fscs_write_response");
        BIO_STATIC_RESET_WRITE(&st->fscs_outgoing);
      }
      break;
    default:
      fprintf(stderr, "fscs_write_response: unknown error %d\n", err);
      ERR_print_errors_fp(stderr);
      BIO_STATIC_RESET_WRITE(&st->fscs_outgoing);
      break;
    }
  }
  pthread_mutex_unlock(&st->fscs_outgoing_mutex);
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
  SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
  struct flockservice *fs;

  if ( !ctx ) return 0;

  fs = SSL_CTX_get_flockservice(ctx);
  if ( !fs ) return 0;

  *cookie_len = DTLS1_COOKIE_LENGTH;
  if ( pthread_mutex_lock(&fs->fs_dtls_cookies_mutex) == 0 ) {
    int ret = 1;
    if ( dtlscookies_generate_cookie(&fs->fs_dtls_cookies, cookie, cookie_len) < 0 ) {
      fprintf(stderr, "dtlscookies_generate failed\n");
      ret = 0;
    }
    pthread_mutex_unlock(&fs->fs_dtls_cookies_mutex);

    return ret;
  } else return 0;

//  static const char simple_cookie[] = "Cookie"; // TODO generate
//  memcpy(cookie, simple_cookie, sizeof(simple_cookie));
//  *cookie_len = sizeof(simple_cookie);
//  return 1;
}

static int verify_cookie_cb(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
  SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
  struct flockservice *fs;

  if ( !ctx ) return 0;

  fs = SSL_CTX_get_flockservice(ctx);
  if ( !fs ) return 0;

  if ( pthread_mutex_lock(&fs->fs_dtls_cookies_mutex) == 0 ) {
    int ret;
    ret = dtlscookies_verify_cookie(&fs->fs_dtls_cookies, cookie, cookie_len);
    if ( ret < 0 ) {
      fprintf(stderr, "dtlscookies_verify_cookie fails\n");
      ret = 0;
    }
    pthread_mutex_unlock(&fs->fs_dtls_cookies_mutex);
    return ret;
  } else
    return 0;
}

static int flockservice_verify_cert(int preverify_ok, X509_STORE_CTX *ctx) {
  return 1;
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

  err = pthread_rwlock_init(&svc->fs_appliances_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "flockservice_init: could not create appliances rwlock: %s\n", strerror(err));
    goto error;
  }
  svc->fs_mutexes_initialized |= FS_APPLIANCES_MUTEX;

  err = pthread_rwlock_init(&svc->fs_connections_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "flockservice_init: could not create connections rwlock: %s\n", strerror(err));
    goto error;
  }
  svc->fs_mutexes_initialized |= FS_CONNECTIONS_MUTEX;

  err = pthread_mutex_init(&svc->fs_dtls_cookies_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "flockservice_init: could not crete dtls cookies mutex: %s\n", strerror(err));
    goto error;
  }
  svc->fs_mutexes_initialized |= FS_DTLS_COOKIES_MUTEX;

  if ( dtlscookies_init(&svc->fs_dtls_cookies, 20, 120, FLOCK_DTLS_COOKIE_LENGTH) < 0 ) {
    fprintf(stderr, "flockservice_init: could not create dtls cookies\n");
    goto error;
  }

  svc->fs_ssl_ctx = SSL_CTX_new(DTLS_server_method());
  if ( !svc->fs_ssl_ctx ) {
    fprintf(stderr, "flockservice_init: SSL_CTX_new failed\n");
    goto openssl_error;
  }

  if ( SSL_CTX_set_flockservice(svc->fs_ssl_ctx, svc) < 0 ) {
    fprintf(stderr, "flockservice_init: could not set flockservice on SSL_CTX\n");
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

  SSL_CTX_set_verify(svc->fs_ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     flockservice_verify_cert);
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
  svc->fs_appliances = NULL;
  svc->fs_connections = NULL;

  dtlscookies_clear(&svc->fs_dtls_cookies);

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

  dtlscookies_release(&svc->fs_dtls_cookies);

  if ( svc->fs_mutexes_initialized & FS_SERVICE_MUTEX ) {
    pthread_mutex_unlock(&svc->fs_service_mutex);
    pthread_mutex_destroy(&svc->fs_service_mutex);
    svc->fs_mutexes_initialized &= ~FS_SERVICE_MUTEX;
  }

  if ( svc->fs_mutexes_initialized & FS_APPLIANCES_MUTEX ) {
    // TODO destroy all appliances
    pthread_rwlock_destroy(&svc->fs_appliances_mutex);
    svc->fs_mutexes_initialized &= ~FS_APPLIANCES_MUTEX;
  }

  if ( svc->fs_mutexes_initialized & FS_CONNECTIONS_MUTEX ) {
    pthread_rwlock_destroy(&svc->fs_connections_mutex);
    svc->fs_mutexes_initialized &= ~FS_CONNECTIONS_MUTEX;
  }

  if ( svc->fs_mutexes_initialized & FS_DTLS_COOKIES_MUTEX ) {
    pthread_mutex_destroy(&svc->fs_dtls_cookies_mutex);
    svc->fs_mutexes_initialized &= ~FS_DTLS_COOKIES_MUTEX;
  }
}

void flockservice_start(struct flockservice *svc, struct eventloop *el) {
  eventloop_subscribe_fd(el, svc->fs_service_sk, FD_SUB_READ, &svc->fs_service_sub);
}

// Service

static int receive_next_packet(struct flockservice *st, kite_sock_addr *datagram_addr) {
  int err;
  socklen_t addr_sz = sizeof(*datagram_addr);
  //  char addr_buf[INET6_ADDRSTRLEN];

  err = recvfrom(st->fs_service_sk, st->fs_incoming_packet, sizeof(st->fs_incoming_packet),
                 0, &datagram_addr->ksa, &addr_sz);
  if ( err < 0 ) {
    perror("next_packet_address: recvmsg");
    return -1;
  } else if ( err == 0 ) {
    fprintf(stderr, "next_packet_address: socket reports that it has shutdown\n");
    return -1;
  }

  BIO_STATIC_SET_READ_SZ(&st->fs_sk_incoming, err);

//  fprintf(stderr, "Got packet from address %s:%d\n",
//          inet_ntop(datagram_addr->sa_family, SOCKADDR_DATA(datagram_addr),
//                    addr_buf, sizeof(addr_buf)),
//          ntohs(((struct sockaddr_in *) datagram_addr)->sin_port));

  return 0;
}

static void flock_service_accept(struct flockservice *st, struct eventloop *eventloop,
                                 kite_sock_addr *peer) {
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
      ERR_print_errors_fp(stderr);
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
  HASH_ADD(fscs_hash_ent, st->fs_clients_hash, fscs_addr, sizeof(kite_sock_addr), client_st);
  pthread_rwlock_unlock(&st->fs_clients_mutex);

  // Now attempt to send the packet. This may fail if there's no space
  // in the socket buffer, but this is okay.
 flush:
  if ( BIO_STATIC_WPENDING(&outgoing_bio) ) {
    fprintf(stderr, "Responding to DTLS handshake\n");
    err = sendto(st->fs_service_sk, pkt_out, BIO_STATIC_WPENDING(&outgoing_bio), 0,
                 &peer->ksa, sizeof(*peer));
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
  kite_sock_addr datagram_addr;
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
    SAFE_MUTEX_LOCK(&client->fscs_outgoing_mutex);
    if ( FSCS_CAN_SEND_MORE(client) ) {
      pthread_mutex_unlock(&client->fscs_outgoing_mutex);
      // Continue
      client->fscs_base_st.fcs_fn(st, &client->fscs_base_st, FSC_RECEIVE_PKT, NULL);
    } else {
      pthread_mutex_unlock(&client->fscs_outgoing_mutex);
      fprintf(stderr, "Ignoring data because there is no space in the outgoing buffer\n");
    }
  }
}

static void flock_service_flush_buffers(struct flockservice *st, struct eventloop *el) {
  int err;
  struct flocksvcclientstate *cli, *old_cli = NULL;
  struct fcspktwriter *curpkt, *tmppkt;

  fprintf(stderr, "Flushing buffers\n");

  pthread_mutex_lock(&st->fs_service_mutex);
  for ( cli = st->fs_first_outgoing; cli && cli != old_cli;
        old_cli = cli, cli = (cli->fscs_next_outgoing == cli ? NULL : cli->fscs_next_outgoing), old_cli->fscs_next_outgoing = NULL ) {

    fprintf(stderr, "Flushing buffers for client\n");

    SAFE_MUTEX_LOCK(&cli->fscs_outgoing_mutex);
    // Attempt to write out the buffer with the DTLS context

    if ( BIO_STATIC_WPENDING(&cli->fscs_outgoing) ) {
      err = sendto(st->fs_service_sk, cli->fscs_outgoing_buf, BIO_STATIC_WPENDING(&cli->fscs_outgoing), 0,
                   (void *) &cli->fscs_addr, sizeof(cli->fscs_addr));
      BIO_STATIC_RESET_WRITE(&cli->fscs_outgoing);
      if ( err < 0 ) {
        if ( errno == EWOULDBLOCK )
          goto wouldblock;
        perror("flock_service_flush_buffers: sendto");
        goto finish_cli_send;
      }
    }

    // Attempt to write any connection attempts
    fprintf(stderr, "Start send packets\n");
    DLIST_ITER(&cli->fscs_outgoing_packets, fcspw_dl, curpkt, tmppkt) {
      char req_buf[MAX_STUN_MSG_SIZE];
      int req_sz = sizeof(req_buf);

      if ( curpkt->fcspw_write(curpkt, req_buf, &req_sz) < 0 ) {
        fprintf(stderr, "Could not write outgoing packet\n");
        req_sz = 0;
      }

      fprintf(stderr, "Sending stun request of size %d\n", req_sz);

      if ( req_sz > 0 ) {
        err = SSL_write(cli->fscs_dtls, req_buf, req_sz);
        if ( err <= 0 ) {
          fprintf(stderr, "fscs_write_response: cannot write STUN start conn: %d\n",
                  SSL_get_error(cli->fscs_dtls, err));
          BIO_STATIC_RESET_WRITE(&cli->fscs_outgoing);
        }

        if ( BIO_STATIC_WPENDING(&cli->fscs_outgoing) ) {
          err = sendto(st->fs_service_sk, cli->fscs_outgoing_buf,
                       BIO_STATIC_WPENDING(&cli->fscs_outgoing), 0,
                       (void *) &cli->fscs_addr, sizeof(cli->fscs_addr));
          BIO_STATIC_RESET_WRITE(&cli->fscs_outgoing);
          if ( err < 0 ) {
            if ( errno == EWOULDBLOCK ) {
              DLIST_SET_FIRST(&cli->fscs_outgoing_packets, curpkt);
              goto wouldblock;
            }
            perror("flock_service_flush_buffers: sendto (start conn requests)");
            curpkt->fcspw_sts = -errno;
          } else
            curpkt->fcspw_sts = 0;
        } else
          curpkt->fcspw_sts = -EBUSY;
      } else
        curpkt->fcspw_sts = 0;

      eventloop_queue(el, &curpkt->fcspw_done);
      if ( curpkt->fcspw_sh )
        SHARED_UNREF(curpkt->fcspw_sh);
    }

    fprintf(stderr, "Done send packets\n");

    DLIST_CLEAR(&cli->fscs_outgoing_packets);

  finish_cli_send:
    fprintf(stderr, "Finish cli send\n");
    pthread_mutex_unlock(&cli->fscs_outgoing_mutex);

    FSCS_UNREF(cli);
    continue;

  wouldblock:
    fprintf(stderr, "Got wouldblock\n");
    pthread_mutex_unlock(&cli->fscs_outgoing_mutex);
    break;
  }

  st->fs_first_outgoing = cli;
  if ( !st->fs_first_outgoing )
    st->fs_last_outgoing = NULL;

  pthread_mutex_unlock(&st->fs_service_mutex);
  fprintf(stderr, "Wrote buffers\n");
}

static void flock_service_handle_event(struct flockservice *st, struct eventloop *el, struct fdevent *ev) {
  fprintf(stderr, "Flock service got socket event\n");

  if ( FD_WRITE_AVAILABLE(ev) )
    flock_service_flush_buffers(st, el);

  if ( FD_READ_PENDING(ev) ) { // && BIO_ctrl_wpending(st->fs_service_bio) == 0 ) {
    // Only read data if there is no write pending
    flock_service_handle_read(st, el);
  }

  pthread_mutex_lock(&st->fs_service_mutex);

  if ( st->fs_first_outgoing )
    eventloop_subscribe_fd(el, st->fs_service_sk, FD_SUB_READ | FD_SUB_WRITE, &st->fs_service_sub);
  else
    eventloop_subscribe_fd(el, st->fs_service_sk, FD_SUB_READ, &st->fs_service_sub);

  pthread_mutex_unlock(&st->fs_service_mutex);
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

int flockservice_lookup_connection(struct flockservice *svc, uint64_t conn_id,
                                   struct connection **c) {
  SHARED_DEFERRED defered_free;

  SAFE_RWLOCK_RDLOCK(&svc->fs_connections_mutex);
  HASH_FIND(conn_hh, svc->fs_connections, &conn_id, sizeof(conn_id), *c);
  if ( *c == NULL ) {
    pthread_rwlock_unlock(&svc->fs_connections_mutex);
    return -1;
  } else {
    // The hash table contains a weak reference to the connection
    if ( CONN_SAFE_LOCK(*c, &defered_free) == 0 ) {
      // If we got a connection reference, then store another weak reference for the hash table
      CONN_WREF(*c);
      pthread_rwlock_unlock(&svc->fs_connections_mutex);
      SHARED_DO_DEFERRED(&defered_free);
      return 0;
    } else {
      pthread_rwlock_unlock(&svc->fs_connections_mutex);
      SHARED_DO_DEFERRED(&defered_free);
      *c = NULL;
      return -1;
    }
  }
}

int flockservice_lookup_appliance(struct flockservice *svc, const char *name,
                                  struct applianceinfo **ai) {
  return flockservice_lookup_appliance_ex(svc, name, strlen(name), ai);
}

int flockservice_lookup_appliance_ex(struct flockservice *svc, const char *name,
                                     int name_sz, struct applianceinfo **ai) {
  HASH_FIND(ai_hash_ent, svc->fs_appliances, name, name_sz, *ai);
  if ( *ai == NULL )
    return -1;
  else {
    AI_REF(*ai);
    return 0;
  }
}

void flockservice_remove_appliance(struct flockservice *svc, struct applianceinfo *ai, int reason) {
  SAFE_RWLOCK_WRLOCK(&svc->fs_appliances_mutex);
  HASH_DELETE(ai_hash_ent, svc->fs_appliances, ai);
  pthread_rwlock_unlock(&svc->fs_appliances_mutex);
}

struct sendofferrsplns {
  struct stunattr *sorl_attr;
  const struct stunmsg *sorl_msg;
  size_t sorl_sz;
};

int get_sendoffer_rsp_lns(void *arg, int *line_index, const char **start, const char **end) {
  struct sendofferrsplns *sorl = (struct sendofferrsplns *)arg;
  for ( ; STUN_IS_VALID(sorl->sorl_attr, sorl->sorl_msg, sorl->sorl_sz);
        sorl->sorl_attr = STUN_NEXTATTR(sorl->sorl_attr) ) {
    switch ( STUN_ATTR_NAME(sorl->sorl_attr) ) {
    case STUN_ATTR_KITE_SDP_LINE:
      if ( STUN_ATTR_PAYLOAD_SZ(sorl->sorl_attr) >= 2 ) {
        *line_index = ntohs(*((uint16_t *) STUN_ATTR_DATA(sorl->sorl_attr)));
        if ( *line_index == 0xFFFF || *line_index == 0xFFFE ) {
          if ( STUN_ATTR_PAYLOAD_SZ(sorl->sorl_attr) == 2 )
            return ( *line_index == 0xFFFF ? CONNOFFER_CANDIDATES_COMPLETE : CONNOFFER_OFFER_COMPLETE );
          else
            return CONNOFFER_LINE_ERROR;
        }

        *start = ((char *)STUN_ATTR_DATA(sorl->sorl_attr)) + 2;
        *end = ((char *)STUN_ATTR_DATA(sorl->sorl_attr)) + STUN_ATTR_PAYLOAD_SZ(sorl->sorl_attr);

        sorl->sorl_attr = STUN_NEXTATTR(sorl->sorl_attr);
        return CONNOFFER_LINE_RETRIEVED;
      } else
        return CONNOFFER_LINE_ERROR;
    }
  }
  return CONNOFFER_NO_MORE_LINES;
}

static int flockservice_handle_offer_response(struct flockservice *svc,
                                              const struct stunmsg *msg, int buf_sz) {
  struct stunattr *attr;
  struct connection *c;
  uint64_t conn_id = 0;
  int has_lines = 0, answer_offs = -1;

  for ( attr = STUN_FIRSTATTR(msg);
        STUN_IS_VALID(attr, msg, buf_sz);
        attr = STUN_NEXTATTR(attr) ) {
    fprintf(stderr, "Got stun attribute %04x\n", STUN_ATTR_NAME(attr));
    switch ( STUN_ATTR_NAME(attr) ) {
    case STUN_ATTR_KITE_CONN_ID:
      if ( STUN_ATTR_PAYLOAD_SZ(attr) == sizeof(conn_id) ) {
        conn_id = ntohll(*((uint64_t *) STUN_ATTR_DATA(attr)));
      }
      break;
    case STUN_ATTR_KITE_SDP_LINE:
      has_lines = 1;
      break;
    case STUN_ATTR_KITE_ANSWER_OFFSET:
      if ( STUN_ATTR_PAYLOAD_SZ(attr) >= 2 ) {
        uint16_t offs;
        memcpy(&offs, STUN_ATTR_DATA(attr), sizeof(offs));
        answer_offs = ntohs(offs);
        fprintf(stderr, "Got answer offset %d\n", answer_offs);
      }
      break;
    case STUN_ATTR_FINGERPRINT:
      break;
    default:
      fprintf(stderr, "flockservice_handle_offer_response: Unknown attribute %04x\n",
              STUN_ATTR_NAME(attr));
      break;
    }
  }

  fprintf(stderr, "flockservire_handle_offer_response: %08lx for line %d\n", conn_id, has_lines);

  if ( !has_lines && answer_offs < 0 ) {
    fprintf(stderr, "flockservice_handle_offer_response: Ignoring response with no lines and no salient answer offset\n");
    return 0;
  }

  if ( flockservice_lookup_connection(svc, conn_id, &c) < 0 ) {
    fprintf(stderr, "flockservice_handle_offer_response: connection does not exist\n");
    return -1;
  }

  if ( connection_verify_tx_id(c, &msg->sm_tx_id) == 0 ) {
    struct sendofferrsplns lines_cl;
    lines_cl.sorl_attr = STUN_FIRSTATTR(msg);
    lines_cl.sorl_msg = msg;
    lines_cl.sorl_sz  = buf_sz;
    connection_offer_received(c, answer_offs, get_sendoffer_rsp_lns, &lines_cl);
  } else
    fprintf(stderr, "flockservice_handle_sendoffer_response: drop packet because tx id doesn't match\n");

  CONN_UNREF(c);

  return 0;
}

static int flockservice_handle_startconn_response(struct flockservice *svc,
                                                  const struct stunmsg *msg, int buf_sz) {
  struct stunattr *attr;
  struct connection *c;
  uint64_t conn_id = 0;
  int has_personas = 0;
  int error = -1;
  char personas_hash[SHA256_DIGEST_LENGTH];

  fprintf(stderr, "flockservice_handle_startconn_response: Got response\n");

  for ( attr = STUN_FIRSTATTR(msg);
        STUN_IS_VALID(attr, msg, buf_sz);
        attr = STUN_NEXTATTR(attr) ) {
    switch ( STUN_ATTR_NAME(attr) ) {
    case STUN_ATTR_ERROR_CODE:
      if ( STUN_ATTR_PAYLOAD_SZ(attr) == sizeof(uint16_t) ) {
        error = ntohs(*((uint16_t *) STUN_ATTR_DATA(attr)));
      }
      break;
    case STUN_ATTR_KITE_CONN_ID:
      if ( STUN_ATTR_PAYLOAD_SZ(attr) == sizeof(conn_id) ) {
        conn_id = ntohll(*((uint64_t *) STUN_ATTR_DATA(attr)));
      }
      break;
    case STUN_ATTR_KITE_PERSONAS_HASH:
      if ( STUN_ATTR_PAYLOAD_SZ(attr) == sizeof(personas_hash) ) {
        memcpy(personas_hash, (char *) STUN_ATTR_DATA(attr), sizeof(personas_hash));
        has_personas = 1;
      }
      break;
    default:
      continue;
    }
  }

  fprintf(stderr, "flockservice_handle_startconn_response: Got response %08lx\n", conn_id);

  if ( has_personas ) {
    char persona_hash_str[SHA256_DIGEST_LENGTH * 2 + 1];
    fprintf(stderr, "flockservice_handle_startconn_response: Got personas hash %s\n",
            hex_digest_str((unsigned char *)personas_hash, persona_hash_str,
                           sizeof(personas_hash)));
  } else {
    fprintf(stderr, "flockservice_handle_startconn_response: no personas\n");
  }

  if ( conn_id == 0 ) return -1;

  if ( flockservice_lookup_connection(svc, conn_id, &c) < 0 ) {
    return -1;
  }

  if ( connection_verify_tx_id(c, &msg->sm_tx_id) == 0 ) {
    if ( STUN_MESSAGE_TYPE(msg) & STUN_ERROR ) {
      connection_error_received(c, error);
    } else {
      connection_confirmation_received(c, has_personas);

      // If we have personas, ask the connection to deliver the personas.
      if ( connection_wants_personas(c) ) {
        if ( connection_send_personas(c, (unsigned char *) personas_hash) < 0 ) {
          connection_signal_error(c, CONNECTION_ERR_COULD_NOT_SEND_PERSONAS);
          connection_complete(c);
        }
      }
    }
  } else
    fprintf(stderr, "flockservice_handle_startconn_response: drop packet because tx id doesn't match\n");

  CONN_UNREF(c);

  return 0;
}

int flockservice_handle_appliance_registration(struct flockservice *svc,
                                               struct applianceinfo *app,
                                               const struct stunmsg *msg, int msg_sz,
                                               char *rsp_buf, size_t *rsp_sz) {
  int err, max_rsp_sz = *rsp_sz;
  const struct stunattr *attr = STUN_FIRSTATTR(msg);
  struct applianceinfo *old_app;
  struct stunmsg *rsp_msg = (struct stunmsg *) rsp_buf;
  struct stunattr *rsp_attr;

  kite_sock_addr app_addr;

  int app_name_found = 0;
  char app_name[KITE_APPLIANCE_NAME_MAX];

  for ( attr = STUN_FIRSTATTR(msg); STUN_ATTR_IS_VALID(attr, msg, msg_sz); attr = STUN_NEXTATTR(attr) ) {
    switch ( STUN_ATTR_NAME(attr) ) {
    case STUN_ATTR_USERNAME:
      if ( !app_name_found ) {
        if ( STUN_ATTR_PAYLOAD_SZ(attr) > 0 ) {
          app_name_found = 1;

          if ( STUN_ATTR_PAYLOAD_SZ(attr) > (sizeof(app_name) - 1) )
            return -STUN_SERVER_ERROR;
          else {
            memcpy(app_name, STUN_ATTR_DATA(attr), STUN_ATTR_PAYLOAD_SZ(attr));
            app_name[STUN_ATTR_PAYLOAD_SZ(attr)] = '\0';
          }
        } else
          fprintf(stderr, "Empty username\n");
      } else
        fprintf(stderr, "Duplicate username attribute\n");
      break;
    case STUN_ATTR_FINGERPRINT:
    case STUN_ATTR_MESSAGE_INTEGRITY:
      break;
    default:
      fprintf(stderr, "flockservice_handle_appliance_registration: Skipping unknown attribute %x\n", STUN_ATTR_NAME(attr));
      if ( STUN_ATTR_REQUIRED(STUN_ATTR_NAME(attr)) ) {
        // TODO report unknown attributes
        return -STUN_UNKNOWN_ATTRIBUTES;
      }
    }
  }

  if ( !app_name_found )
    return -STUN_BAD_REQUEST;

  err = applianceinfo_get_peer_addr(app, &app_addr);
  if ( err < 0 ) {
    fprintf(stderr, "Could not get peer address from appliance\n");
    return -1;
  }

  SAFE_RWLOCK_WRLOCK(&svc->fs_appliances_mutex);

  fprintf(stderr, "Got registration for %s\n", app_name);
  // TODO sharding

  // Copy name
  strncpy(app->ai_name, app_name, sizeof(app->ai_name));

  old_app = NULL;
  err = flockservice_lookup_appliance(svc, app_name, &old_app);
  if ( err < 0 ) {
    fprintf(stderr, "This is a new appliance\n");

    assert( (app->ai_flags & AI_FLAG_ACTIVE) == 0 );
    app->ai_flags |= AI_FLAG_ACTIVE;

    // No need to lock app because it is not active, hence not shared
    app->ai_shared.sh_refcnt = 1;
    HASH_ADD(ai_hash_ent, svc->fs_appliances, ai_name, strlen(app->ai_name), app);
    pthread_rwlock_unlock(&svc->fs_appliances_mutex);
  } else {
    fprintf(stderr, "Found old appliance %p for appliance %p\n", old_app, app);
    pthread_rwlock_unlock(&svc->fs_appliances_mutex);

    if ( old_app != app ) {
      struct aireconcile reconciliation;
      uint16_t err_code;

      reconciliation.air_old = old_app;
      reconciliation.air_new = app;

      // This appliance is old. Check to see if we need to do any reconciliation
      err = old_app->ai_appliance_fn(old_app, AI_OP_RECONCILE, &reconciliation);
      if ( err < 0 ) {
        STUN_INIT_MSG(rsp_msg, STUN_KITE_REGISTRATION | STUN_RESPONSE);
        memcpy(&rsp_msg->sm_tx_id, &msg->sm_tx_id, sizeof(rsp_msg->sm_tx_id));
        rsp_attr = STUN_FIRSTATTR(rsp_msg);
        STUN_INIT_ATTR(rsp_attr, STUN_ATTR_ERROR_CODE, sizeof(uint16_t));
        switch ( err ) {
        default:
        case -2: err_code = STUN_SERVER_ERROR; break;
        case -1: err_code = STUN_CONFLICT; break;
        }
        err_code = htons(err_code);
        memcpy(STUN_ATTR_DATA(rsp_attr), &err_code, sizeof(err_code));
        STUN_FINISH_WITH_FINGERPRINT(rsp_attr, rsp_msg, *rsp_sz, err);
        *rsp_sz = STUN_MSG_LENGTH(rsp_msg);

        AI_UNREF(old_app);

        return err;
      } else {
        AI_UNREF(old_app); // Remove the reference that we have as part of holding this appliance
        AI_UNREF(old_app);

        SAFE_RWLOCK_WRLOCK(&svc->fs_appliances_mutex);
        app->ai_shared.sh_refcnt = 1;
        HASH_ADD(ai_hash_ent, svc->fs_appliances, ai_name, strlen(app->ai_name), app);
        pthread_rwlock_unlock(&svc->fs_appliances_mutex);
      }
    } else {
      AI_UNREF(old_app);
    }
  }

  STUN_INIT_MSG(rsp_msg, STUN_KITE_REGISTRATION | STUN_RESPONSE);
  memcpy(&rsp_msg->sm_tx_id, &msg->sm_tx_id, sizeof(rsp_msg->sm_tx_id));
  rsp_attr = STUN_FIRSTATTR(rsp_msg);
  err = stun_add_mapped_address_attrs(&rsp_attr, rsp_msg, max_rsp_sz, &app_addr.ksa, sizeof(app_addr));
  if ( err < 0 ) {
    fprintf(stderr, "Could not add mapped address attributes\n");
    return -1;
  }
  STUN_FINISH_WITH_FINGERPRINT(rsp_attr, rsp_msg, *rsp_sz, err);
  *rsp_sz = STUN_MSG_LENGTH(rsp_msg);
  if ( err == 0 ) return 0;
  else return -1;
}

// Connection routines

// Note: all connections in fs_connections are owned by whatever created the connection
int flockservice_new_connection(struct flockservice *svc, struct connection *conn) {
  struct connection *existing;
  if ( pthread_rwlock_wrlock(&svc->fs_connections_mutex) == 0 ) {
    do {
      int err = RAND_bytes((unsigned char *)&conn->conn_id, sizeof(conn->conn_id));
      if ( !err ) abort();

      HASH_FIND(conn_hh, svc->fs_connections, &conn->conn_id, sizeof(conn->conn_id), existing);
    } while (existing || conn->conn_id == 0);

    fprintf(stderr, "flockservice_new_connection: new connection is %08lx\n", conn->conn_id);

    CONN_REF(conn);
    HASH_ADD(conn_hh, svc->fs_connections, conn_id, sizeof(conn->conn_id), conn);

    pthread_rwlock_unlock(&svc->fs_connections_mutex);
    return 0;
  } else
    return -1;
}

int flockservice_finish_connection(struct flockservice *svc, struct connection *conn) {
  struct connection *existing;

  SAFE_RWLOCK_WRLOCK(&svc->fs_connections_mutex);
  HASH_FIND(conn_hh, svc->fs_connections, &conn->conn_id, sizeof(conn->conn_id), existing);
  if ( existing )
    HASH_DELETE(conn_hh, svc->fs_connections, conn);
  pthread_rwlock_unlock(&svc->fs_connections_mutex);

  if ( existing ) CONN_UNREF(existing);

  return 0;
}

int flockservice_open_cached_personaset(struct flockservice *svc,
                                        const char *appliance_name, const unsigned char *ps_hash,
                                        int ps_hash_sz, struct cpersonaset **cps) {
  fprintf(stderr, "TODO: flockservice_open_cached_personaset\n");

  *cps = (struct cpersonaset *) cmempersonaset_alloc();
  if ( !(*cps) ) return -1;

  return FLOCKSERVICE_CACHED_PERSONASET_NEW;
}
