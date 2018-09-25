#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <assert.h>

#include "flock.h"
#include "state.h"
#include "util.h"

#define OP_FLOCK_RESOLVE_NAME EVT_CTL_CUSTOM
#define OP_FLOCK_SOCKET_EVENT (EVT_CTL_CUSTOM + 1)
#define OP_FLOCK_REGISTRATION_TIMEOUT (EVT_CTL_CUSTOM + 2)
#define OP_FLOCK_REFRESH (EVT_CTL_CUSTOM + 3)

// #define FLOCK_DEBUG 1
#ifdef FLOCK_DEBUG
#define dbgprintf(...) fprintf(stderr, __VA_ARGS__)
#else
#define dbgprintf(...) (void)0
#endif

static void flock_start_connection(struct flock *f, struct eventloop *el);
static int flock_receive_response(struct flock *f, struct appstate *app, uint16_t req_code);
static int flock_receive_request(struct flock *f, struct appstate *app);
static int flock_process_request(struct flock *f, struct appstate *app, const char *pkt_buf, int pkt_sz);
static void flock_successful_registration(struct flock *f, struct appstate *app);
static void flock_fn(struct eventloop *el, int op, void *arg);

void flock_clear(struct flock *f) {
  f->f_uri_str = NULL;
  f->f_hostname = NULL;
  f->f_flock_state = FLOCK_STATE_UNSTARTED;
  f->f_flags = 0;
  memset(f->f_expected_digest, 0, sizeof(f->f_expected_digest));
  f->f_cur_addr.sin_addr.s_addr = 0;
  f->f_cur_addr.sin_port = 0;
  f->f_cur_addr.sin_family = AF_UNSPEC;
  f->f_pconns = NULL;
  DLIST_INIT(&f->f_pconns_with_response);
}

void flock_release(struct flock *f) {
  struct pconn *cur_pconn, *tmp_pconn;

  if ( f->f_uri_str ) {
    free(f->f_uri_str);
    f->f_uri_str = NULL;
  }

  if ( f->f_hostname ) {
    free(f->f_hostname);
    f->f_hostname = NULL;
  }

  if ( f->f_flags & FLOCK_FLAG_INITIALIZED ) {
    pthread_mutex_destroy(&f->f_mutex);
    f->f_flags &= ~FLOCK_FLAG_INITIALIZED;
  }

  switch ( f->f_flock_state ) {
  case FLOCK_STATE_PENDING:
    dnssub_release(&f->f_resolver);
    break;
  case FLOCK_STATE_CONNECTING:
  case FLOCK_STATE_REGISTERING:
  case FLOCK_STATE_SEND_REGISTRATION:
  case FLOCK_STATE_REGISTERED:
    if ( f->f_socket ) close(f->f_socket);
    if ( f->f_dtls_client ) SSL_free(f->f_dtls_client);
    break;
  case FLOCK_STATE_UNSTARTED:
  case FLOCK_STATE_SUSPENDED:
  case FLOCK_STATE_SRV_CRT_REJ:
  case FLOCK_STATE_NM_NOT_RES:
    break;
  default:
    fprintf(stderr, "flock_release: invalid flock state: %d\n", f->f_flock_state);
  }

  HASH_ITER(pc_hh, f->f_pconns, cur_pconn, tmp_pconn) {
    PCONN_UNREF(cur_pconn);
  }
}

#define URL_SLICE_LENGTH(slice) ((int) ((slice)->afterLast - (slice)->first))
int flock_assign_uri(struct flock *f, UriUriA *uri) {
  int norm_uri_sz, port;

  if ( strncmp(uri->scheme.first, FLOCK_URI_SCHEME,
               uri->scheme.afterLast - uri->scheme.first) == 0 ) {
  } else if ( strncmp(uri->scheme.first, STUN_URI_SCHEME,
                      uri->scheme.afterLast - uri->scheme.first) == 0 ) {
    f->f_flags |= FLOCK_FLAG_INSECURE | FLOCK_FLAG_STUN_ONLY;
  } else if ( strncmp(uri->scheme.first, STUNS_URI_SCHEME,
                      uri->scheme.afterLast - uri->scheme.first) == 0 ) {
    f->f_flags |= FLOCK_FLAG_STUN_ONLY;
  } else
    return -1;


  if ( uri->portText.first ) {
    const char *pc;
    port = 0;

    for ( pc = uri->portText.first; pc != uri->portText.afterLast; ++pc )
      port = port * 10 + (*pc - '0');
  } else
    port = FLOCK_DEFAULT_PORT;

  if ( (uri->hostText.afterLast - uri->hostText.first) == 0 ) {
    return -1;
  }

  norm_uri_sz = snprintf(NULL, 0, "%.*s://%.*s:%d",
                         URL_SLICE_LENGTH(&uri->scheme),
                         uri->scheme.first,
                         URL_SLICE_LENGTH(&uri->hostText),
                         uri->hostText.first, port);

  f->f_uri_str = malloc(norm_uri_sz + 1);
  if ( !f->f_uri_str ) {
    return -1;
  }

  f->f_hostname = malloc(URL_SLICE_LENGTH(&uri->hostText) + 1);
  if ( !f->f_hostname ) {
    free(f->f_uri_str);
    return -1;
  }

  snprintf(f->f_uri_str, norm_uri_sz + 1, "%.*s://%.*s:%d",
           URL_SLICE_LENGTH(&uri->scheme), uri->scheme.first,
           URL_SLICE_LENGTH(&uri->hostText),
           uri->hostText.first, port);
  memcpy(f->f_hostname, uri->hostText.first, URL_SLICE_LENGTH(&uri->hostText));
  f->f_hostname[URL_SLICE_LENGTH(&uri->hostText)] = '\0';

  f->f_cur_addr.sin_port = htons(port);

  return 0;
}

void flock_move(struct flock *dst, struct flock *src) {
  dst->f_uri_str = src->f_uri_str;
  dst->f_hostname = src->f_hostname;
  memcpy(&dst->f_cur_addr, &src->f_cur_addr, sizeof(dst->f_cur_addr));
  memcpy(dst->f_expected_digest, src->f_expected_digest, sizeof(dst->f_expected_digest));

  dst->f_flags = src->f_flags | FLOCK_FLAG_INITIALIZED;
  dst->f_flock_state = src->f_flock_state;
  dst->f_pconns = src->f_pconns;
  DLIST_MOVE(&dst->f_pconns_with_response, &src->f_pconns_with_response);

  if ( pthread_mutex_init(&dst->f_mutex, NULL) != 0 )
    fprintf(stderr, "flock_move: could not initialize dst->f_mutex\n");

  src->f_uri_str = NULL;
  src->f_hostname = NULL;
  src->f_cur_addr.sin_family = AF_UNSPEC;
  src->f_cur_addr.sin_port = 0;
  src->f_cur_addr.sin_addr.s_addr = 0;

  if ( src->f_flags & FLOCK_FLAG_INITIALIZED )
    pthread_mutex_destroy(&src->f_mutex);

  src->f_flags = 0;
  src->f_flock_state = 0;
  src->f_pconns = NULL;
}

// closes any active connections
static void flock_shutdown_connection(struct flock *f, struct eventloop *el) {
  if ( f->f_dtls_client ) {
    SSL_free(f->f_dtls_client);
    f->f_dtls_client = NULL;
  }

  if ( f->f_socket ) {
    eventloop_unsubscribe_fd(el, f->f_socket, FD_SUB_ALL, &f->f_socket_sub);
    close(f->f_socket);
    f->f_socket = 0;
  }
}

static int flock_handle_ssl_error(struct flock *f, struct eventloop *el, int err) {
  err = SSL_get_error(f->f_dtls_client, err);
  switch ( err ) {
  case SSL_ERROR_NONE:
    fprintf(stderr, "flock_handle_ssl_error: Got SSL_ERROR_NONE on accident\n");
    return -1;
  case SSL_ERROR_ZERO_RETURN:
    dbgprintf("flock_handle_ssl_error: SSL_ERROR_ZERO_RETURN\n");
    return -1;
  case SSL_ERROR_WANT_READ:
    dbgprintf("flock_handle_ssl_error: wants read\n");
    eventloop_subscribe_fd(el, f->f_socket, FD_SUB_ERROR | FD_SUB_READ, &f->f_socket_sub);
    return 0;
  case SSL_ERROR_WANT_WRITE:
    dbgprintf("flock_handle_ssl_error: wants write\n");
    eventloop_subscribe_fd(el, f->f_socket, FD_SUB_ERROR | FD_SUB_WRITE | FD_SUB_READ, &f->f_socket_sub);
    return 0;
  case SSL_ERROR_WANT_CONNECT:
    fprintf(stderr, "flock_handle_ssl_error: SSL_ERROR_WANT_CONNECT\n");
    return -1;
  case SSL_ERROR_WANT_ACCEPT:
    fprintf(stderr, "flock_handle_ssl_error: SSL_ERROR_WANT_ACCEPT\n");
    return -1;
  case SSL_ERROR_WANT_X509_LOOKUP:
    fprintf(stderr, "flock_handle_ssl_error: SSL_ERROR_WANT_X509_LOOKUP\n");
    return -1;
  case SSL_ERROR_WANT_ASYNC:
    fprintf(stderr, "flock_handle_ssl_error: SSL_ERROR_WANT_ASYNC\n");
    return -1;
  case SSL_ERROR_SSL:
    fprintf(stderr, "flock_handle_ssl_error: SSL_ERROR_SSL\n");
    return -1;
  case SSL_ERROR_SYSCALL:
    fprintf(stderr, "flock_handle_ssl_error: syscall failed: %s\n", strerror(errno));
    ERR_print_errors_fp(stderr);
    return -1;
  default:
    fprintf(stderr, "flock_handle_ssl_error: Unknown error %d\n", err);
    return -1;
  }
}

static void flock_update_registration_message(struct flock *f, struct appstate *as) {
  struct stunattr *a;
  int sz, err;

  STUN_INIT_MSG(&f->f_registration_msg, STUN_KITE_REGISTRATION);
  memcpy(&f->f_registration_msg.sm_tx_id, &f->f_last_registration_tx, sizeof(f->f_registration_msg.sm_tx_id));

  a = STUN_FIRSTATTR(&f->f_registration_msg);
  assert(STUN_IS_VALID(a, &f->f_registration_msg, sizeof(f->f_registration_msg)));
  sz = strlen(as->as_appliance_name);
  STUN_INIT_ATTR(a, STUN_ATTR_USERNAME, sz);
  memcpy(STUN_ATTR_DATA(a), as->as_appliance_name, sz);

  // TODO add message-integrity hash using public key hash

  STUN_FINISH_WITH_FINGERPRINT(a, &f->f_registration_msg, sizeof(f->f_registration_msg), err);
  if ( err < 0 )
    fprintf(stderr, "flock_update_registration_message: WARNING: message is invalid\n");
}

static void flock_send_registration(struct flock *f, struct appstate *as) {
  int err;

  // Send registration over dgram
  flock_update_registration_message(f, as);
  err = SSL_write(f->f_dtls_client, (const void *) &f->f_registration_msg,
                  STUN_MSG_LENGTH(&f->f_registration_msg));
  if ( err <= 0 ) {
    fprintf(stderr, "SSL error: could not write message\n");
    ERR_print_errors_fp(stderr);
    goto retry;
  } else {
    if ( err != STUN_MSG_LENGTH(&f->f_registration_msg) ) {
      dbgprintf("Could not write out entirety of registration message\n");
      goto retry;
    } else {
      f->f_flock_state = FLOCK_STATE_REGISTERING;

      // This was written successfully, now we have to wait for a response or a timeout
      timersub_set_from_now(&f->f_registration_timeout, FLOCK_TIMEOUT(f, FLOCK_INITIAL_REGISTRATION_RTO));
      eventloop_subscribe_timer(&as->as_eventloop, &f->f_registration_timeout);
    }
  }

  return;

 retry:
  f->f_flock_state = FLOCK_STATE_REGISTERING;

  FLOCK_NEXT_RETRY(f, &as->as_eventloop);

  if ( !FLOCK_HAS_FAILED(f) ) {
    timersub_set_from_now(&f->f_refresh_timer, FLOCK_SEND_FAIL_INTERVAL);
    eventloop_subscribe_timer(&as->as_eventloop, &f->f_refresh_timer);
  }
}

void flock_dbg_pkt(const unsigned char *pkt_buf, int pkt_sz) {
  int i;
  time_t now;
  struct tm cur_time;

  time(&now);
  localtime_r(&now, &cur_time);
  printf("I %02d:%02d:%02d.000000 0000", cur_time.tm_hour, cur_time.tm_min, cur_time.tm_sec);
  for ( i = 0; i < pkt_sz; ++i )
    printf(" %02x", pkt_buf[i]);
  printf("\n");
  fflush(stdout);
}

static int flock_respond_quick(struct flock *f, struct appstate *app,
                               const void *buf, int buf_sz) {
  int err;

  err = SSL_write(f->f_dtls_client, buf, buf_sz);
  if ( err <= 0 ) {
    err = SSL_get_error(f->f_dtls_client, err);
    switch ( err ) {
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
      fprintf(stderr, "flock_respond_quick: could not send packet... no space in buffer\n");
      return 1;
    default:
      fprintf(stderr, "flock_respond_quick: proto error\n");
      ERR_print_errors_fp(stderr);
      return -1;
    }
  } else {
    dbgprintf("flock_respond_quick: sent response\n");
    return 0;
  }
}

static int flock_process_get_personas(struct flock *f, struct appstate *app,
                                      struct stunmsg *msg, int pkt_sz) {
  struct stunattr *attr;
  struct personaset *personas;
  uint32_t offs = 0xFFFFFFFF;
  unsigned char personas_hash[SHA256_DIGEST_LENGTH];
  int has_personas = 0, err;

  struct stunmsg rsp;

  for ( attr = STUN_FIRSTATTR(msg); STUN_ATTR_IS_VALID(attr, msg, pkt_sz); attr = STUN_NEXTATTR(attr) ) {
    switch ( STUN_ATTR_NAME(attr) ) {
    case STUN_ATTR_KITE_PERSONAS_HASH:
      if ( STUN_ATTR_PAYLOAD_SZ(attr) == sizeof(personas_hash) ) {
        has_personas = 1;
        memcpy(personas_hash, STUN_ATTR_DATA(attr), sizeof(personas_hash));
      }
      break;
    case STUN_ATTR_KITE_PERSONAS_OFFS:
      if ( STUN_ATTR_PAYLOAD_SZ(attr) == sizeof(offs) ) {
        offs = ntohl(*(uint32_t *) STUN_ATTR_DATA(attr));
      }
      break;
    case STUN_ATTR_FINGERPRINT:
      break;
    default:
      fprintf(stderr, "flock_process_get_personas: unknown attribute %04x\n", STUN_ATTR_NAME(attr));
    }
  }

  if ( !has_personas ) {
    fprintf(stderr, "flock_process_get_personas: missing personas hash\n");
    return -1;
  }

  if ( offs == 0xFFFFFFFF ) {
    fprintf(stderr, "flock_process_get_personas: missing offset\n");
    return -1;
  }

  if ( appstate_get_personaset(app, &personas) < 0 ) {
    fprintf(stderr, "flock_process_get_personas: could not get current personas\n");
    return -1;
  }

  // Check if the current personas is the same as this one
  if ( memcmp(personas->ps_hash, personas_hash, SHA256_DIGEST_LENGTH) == 0 ) {
    int chunk_sz = 0;
    struct stunattr *next_attr;

    // If it is transfer as much as possible
    STUN_INIT_MSG(&rsp, STUN_RESPONSE | STUN_KITE_GET_PERSONAS);
    memcpy(&rsp.sm_tx_id, &msg->sm_tx_id, sizeof(rsp.sm_tx_id));
    attr = STUN_FIRSTATTR(&rsp);
    assert(STUN_IS_VALID(attr, &rsp, sizeof(rsp)));
    STUN_INIT_ATTR(attr, STUN_ATTR_KITE_PERSONAS_HASH, sizeof(personas_hash));
    assert(STUN_ATTR_IS_VALID(attr, &rsp, sizeof(rsp)));
    memcpy(STUN_ATTR_DATA(attr), personas_hash, sizeof(personas_hash));

    // Set offset
    if ( offs > personas->ps_buf_sz )
      offs = personas->ps_buf_sz;

    attr = STUN_NEXTATTR(attr);
    assert(STUN_IS_VALID(attr, &rsp, sizeof(rsp)));
    STUN_INIT_ATTR(attr, STUN_ATTR_KITE_PERSONAS_OFFS, sizeof(offs));
    assert(STUN_ATTR_IS_VALID(attr, &rsp, sizeof(rsp)));
    *((uint32_t *) STUN_ATTR_DATA(attr)) = htonl(offs);

    // Set size
    attr = STUN_NEXTATTR(attr);
    assert(STUN_IS_VALID(attr, &rsp, sizeof(rsp)));
    STUN_INIT_ATTR(attr, STUN_ATTR_KITE_PERSONAS_SIZE, sizeof(uint32_t));
    assert(STUN_ATTR_IS_VALID(attr, &rsp, sizeof(rsp)));
    *((uint32_t *) STUN_ATTR_DATA(attr)) = htonl(personas->ps_buf_sz);

    // write out packet
    // Leave 16 bytes for fingerprint
    next_attr = STUN_NEXTATTR(attr);
    chunk_sz = STUN_REMAINING_BYTES(next_attr, &rsp, sizeof(rsp)) - 16;
    if ( chunk_sz > (personas->ps_buf_sz - offs) )
      chunk_sz = personas->ps_buf_sz - offs;

    if ( chunk_sz > 0 ) {
      attr = next_attr;
      assert(STUN_IS_VALID(attr, &rsp, sizeof(rsp)));
      STUN_INIT_ATTR(attr, STUN_ATTR_KITE_PERSONAS_DATA, chunk_sz);
      memcpy(STUN_ATTR_DATA(attr), personas->ps_buf + offs, chunk_sz);
    }

    STUN_FINISH_WITH_FINGERPRINT(attr, &rsp, sizeof(rsp), err);

    assert(err == 0);
  } else {
    STUN_INIT_MSG(&rsp, STUN_RESPONSE | STUN_ERROR | STUN_KITE_GET_PERSONAS);
    attr = STUN_FIRSTATTR(&rsp);
    assert(STUN_IS_VALID(attr, &rsp, sizeof(rsp)));
    STUN_INIT_ATTR(attr, STUN_ATTR_KITE_PERSONAS_HASH, sizeof(personas_hash));
    assert(STUN_ATTR_IS_VALID(attr, &rsp, sizeof(rsp)));
    memcpy(STUN_ATTR_DATA(attr), personas_hash, sizeof(personas_hash));

    attr = STUN_NEXTATTR(attr);
    assert(STUN_IS_VALID(attr, &rsp, sizeof(rsp)));
    STUN_INIT_ATTR(attr, STUN_ATTR_ERROR_CODE, sizeof(uint16_t));
    assert(STUN_ATTR_IS_VALID(attr, &rsp, sizeof(rsp)));
    *((uint16_t *) STUN_ATTR_DATA(attr)) = htons(STUN_NOT_FOUND);

    STUN_FINISH_WITH_FINGERPRINT(attr, &rsp, sizeof(rsp), err);
    assert( err == 0 );
  }
  flock_respond_quick(f, app, &rsp, STUN_MSG_LENGTH(&rsp));

  PERSONASET_UNREF(personas);
  return 0;
}

static int flock_process_sendoffer(struct flock *f, struct appstate *app,
                                   struct stunmsg *msg, int pkt_sz) {
  uint64_t conn_id = 0;
  int line = -1;
  struct stunattr *attr;
  struct pconn *conn;
  const char *answer = NULL;
  size_t answer_sz = 0;
  uint16_t answer_offs = 0;

  for ( attr = STUN_FIRSTATTR(msg); STUN_ATTR_IS_VALID(attr, msg, pkt_sz); attr = STUN_NEXTATTR(attr) ) {
    switch ( STUN_ATTR_NAME(attr) ) {
    case STUN_ATTR_KITE_CONN_ID:
      if ( STUN_ATTR_PAYLOAD_SZ(attr) == sizeof(conn_id) ) {
        conn_id = ntohll(*((uint64_t *) STUN_ATTR_DATA(attr)));
      }
      break;
    case STUN_ATTR_KITE_SDP_LINE:
      if ( STUN_ATTR_PAYLOAD_SZ(attr) == sizeof(uint16_t) ) {
        line = ntohs(*((uint16_t *) STUN_ATTR_DATA(attr)));
      }
      break;
    case STUN_ATTR_KITE_ANSWER:
      if ( STUN_ATTR_PAYLOAD_SZ(attr) > sizeof(answer_offs) ) {
        memcpy(&answer_offs, STUN_ATTR_DATA(attr), sizeof(answer_offs));
        answer_offs = ntohs(answer_offs);

        answer = ((char *)STUN_ATTR_DATA(attr)) + 2;
        answer_sz = STUN_ATTR_PAYLOAD_SZ(attr) - 2;
        if ( answer_sz == 0 ) {
          answer = NULL;
          answer_offs = 0;
        }
      }
      break;
    case STUN_ATTR_FINGERPRINT:
      break;
    default:
      fprintf(stderr, "flock_process_sendoffer: unknown stun attr %04x\n", STUN_ATTR_NAME(attr));
      break;
    }
  }

  if ( conn_id == 0 ) {
    fprintf(stderr, "flock_process_sendoffer: missing conn_id attribute\n");
    return -1;
  }

  if ( line < 0 ) {
    fprintf(stderr, "flock_process_sendoffer: missing line attribute\n");
    return -1;
  }

  HASH_FIND(pc_hh, f->f_pconns, &conn_id, sizeof(conn_id), conn);
  if ( !conn ) {
    fprintf(stderr, "flock_process_sendoffer: non-existent connection\n");
    return -1;
  }

  pconn_set_request(conn, STUN_REQUEST_TYPE(msg), &msg->sm_tx_id);
  pconn_recv_sendoffer(conn, line, answer, answer_offs, answer_sz);

  return 0;
}

static int flock_process_startconn(struct flock *f, struct appstate *app,
                                   struct stunmsg *msg, int pkt_sz) {
  uint64_t conn_id = 0;
  struct stunattr *attr;
  struct pconn *conn;
  const char *persona_id = NULL;
  const char *credential = NULL;
  size_t credential_sz = 0;

  for ( attr = STUN_FIRSTATTR(msg); STUN_ATTR_IS_VALID(attr, msg, pkt_sz); attr = STUN_NEXTATTR(attr) ) {
    switch ( STUN_ATTR_NAME(attr) ) {
    case STUN_ATTR_KITE_CONN_ID:
      if ( STUN_ATTR_PAYLOAD_SZ(attr) == sizeof(conn_id) ) {
        conn_id = ntohll(*((uint64_t *) STUN_ATTR_DATA(attr)));
      }
      break;
    case STUN_ATTR_USERNAME:
      if ( STUN_ATTR_PAYLOAD_SZ(attr) == PERSONA_ID_LENGTH ) {
        persona_id = (const char *) STUN_ATTR_DATA(attr);
      }
      break;
    case STUN_ATTR_PASSWORD:
      credential_sz = STUN_ATTR_PAYLOAD_SZ(attr);
      if ( credential_sz )
        credential = STUN_ATTR_DATA(attr);
      else
        credential = NULL;
      break;
    case STUN_ATTR_FINGERPRINT:
      break;
    default:
      // TODO check if the attribute is required
      dbgprintf("flock_process_startconn: unknown stun attr %04x\n", STUN_ATTR_NAME(attr));
      break;
    }
  }

  if ( conn_id == 0 ) {
    fprintf(stderr, "flock_process_startconn: missing conn_id attribute\n");
    return -1;
  }

  dbgprintf("flock_process_startconn: starting connection %08lx %p\n", conn_id, f->f_pconns);

  HASH_FIND(pc_hh, f->f_pconns, &conn_id, sizeof(conn_id), conn);
  if ( !conn ) {
    conn = pconn_alloc(conn_id, f, app, PCONN_TYPE_WEBRTC);
    if ( !conn ) {
      fprintf(stderr, "flock_process_startconn: no more memory\n");
      // TODO return error
    } else {
      HASH_ADD(pc_hh, f->f_pconns, pc_conn_id, sizeof(conn->pc_conn_id), conn);
    }

    // Trigger the pconn start event
    pconn_start_service(conn);
  }

  pconn_set_request(conn, STUN_REQUEST_TYPE(msg), &msg->sm_tx_id);

  pconn_recv_startconn(conn, persona_id, credential, credential_sz);

  return 0;
}

static int flock_process_request(struct flock *f, struct appstate *app,
                                 const char *pkt_buf, int pkt_sz) {
  int err;
  struct stunvalidation sv;
  struct stunmsg *msg = (struct stunmsg *) pkt_buf;

  //  flock_dbg_pkt((const unsigned char *)pkt_buf, pkt_sz);

  sv.sv_flags = STUN_NEED_FINGERPRINT | STUN_VALIDATE_REQUEST;
  sv.sv_req_code = 0;
  sv.sv_tx_id = NULL;
  sv.sv_user_cb = NULL;
  sv.sv_unknown_cb = STUN_ACCEPT_UNKNOWN;
  sv.sv_user_data = NULL;
  sv.sv_unknown_attrs = NULL;
  sv.sv_unknown_attrs_sz = 0;

  err = stun_validate(pkt_buf, pkt_sz, &sv);
  if ( err != 0 ) {
    fprintf(stderr, "Stun validate failed with error %d\n", err);
    return -1;
  }

  switch ( STUN_REQUEST_TYPE(msg) ) {
  case STUN_KITE_STARTCONN:
    return flock_process_startconn(f, app, msg, pkt_sz);
  case STUN_KITE_GET_PERSONAS:
    return flock_process_get_personas(f, app, msg, pkt_sz);
  case STUN_KITE_SENDOFFER:
    // We have requested more offer data
    return flock_process_sendoffer(f, app, msg, pkt_sz);
  default:
    fprintf(stderr, "STUN message of unknown type %d\n", STUN_REQUEST_TYPE(msg));
    return -1;
  }
}

static int flock_receive_request(struct flock *f, struct appstate *app) {
  int err;
  char rsp_buf[MAX_STUN_MSG_SIZE];

  err = SSL_read(f->f_dtls_client, (void *) rsp_buf, sizeof(rsp_buf));
  if ( err <= 0 ) {
    fprintf(stderr, "flock_receive_request: could not read request: %d\n", SSL_get_error(f->f_dtls_client, err));
    return -1;
  } else {
    dbgprintf("Got request of size %d\n", err);
    return flock_process_request(f, app, rsp_buf, err);
  }
}

static int flock_receive_response(struct flock *f, struct appstate *as, uint16_t req_code) {
  int err;
  char rsp_buf[MAX_STUN_MSG_SIZE];

  err = SSL_read(f->f_dtls_client, (void *) rsp_buf, sizeof(rsp_buf));
  if ( err <= 0 ) {
    fprintf(stderr, "flock_receive_response: could not read response: %d\n", SSL_get_error(f->f_dtls_client, err));
    return -1;
  } else {
    struct stunvalidation sv;
    struct stunmsg *msg = (struct stunmsg *) rsp_buf;

    dbgprintf("Got response of size %d\n", err);

    if ( err >= STUN_MSG_HDR_SZ && (STUN_MESSAGE_TYPE(msg) & (STUN_RESPONSE | STUN_ERROR)) == 0 ) {
      return flock_process_request(f, as, rsp_buf, err);
    } else {
      sv.sv_flags = STUN_NEED_FINGERPRINT | STUN_VALIDATE_RESPONSE | STUN_VALIDATE_TX_ID;
      sv.sv_req_code = req_code;
      sv.sv_tx_id = &f->f_last_registration_tx;
      sv.sv_user_cb = NULL;
      sv.sv_unknown_cb = STUN_ACCEPT_UNKNOWN;
      sv.sv_user_data = NULL;
      sv.sv_unknown_attrs = NULL;
      sv.sv_unknown_attrs_sz = 0;

      err = stun_validate(rsp_buf, err, &sv);
      if ( err != 0 ) {
        int ret = -1;
        if ( err > 0 ) {
          fprintf(stderr, "STUN validation failed. Error was %d\n", err);
        } else {
          ret = -err;
          switch ( -err ) {
          case STUN_CONFLICT:
            dbgprintf("There was a conflict with another appliance\n");
            break;
          case STUN_TOO_EARLY:
            dbgprintf("The flock had another registration for this appliance and is unwilling to accept new registrations for now\n");
            break;
          default:
            dbgprintf("STUN server responded with error %d\n", -err);
            break;
          }
        }

        return ret;
      }

      // TODO Save ICE candidates
      return 0;
    }
  }
}

static void flock_refresh_registration(struct flock *f) {
  dbgprintf("Refreshed registration\n");
  stun_random_tx_id(&f->f_last_registration_tx);
}

static void flock_send_pconn_responses(struct flock *f) {
  struct pconn *pc, *pc_tmp;
  int err;
  char rsp_buf[MAX_STUN_MSG_SIZE];
  struct stunmsg *msg = (struct stunmsg *)rsp_buf;

  DLIST_ITER(&f->f_pconns_with_response, pc_pconns_with_response_dl, pc, pc_tmp) {
    SAFE_MUTEX_LOCK(&pc->pc_mutex);
    DLIST_REMOVE(&f->f_pconns_with_response, pc_pconns_with_response_dl, pc);

    dbgprintf("Writing pconn response\n");
    err = pconn_write_response(pc, rsp_buf, sizeof(rsp_buf));
    pthread_mutex_unlock(&pc->pc_mutex);
    if ( err < 0 ) {
      fprintf(stderr, "flock_send_pconn_response: ignoring pconn because there was an error writing response\n");
      PCONN_UNREF(pc);
      continue;
    }

    err = SSL_write(f->f_dtls_client, (const void *) rsp_buf, STUN_MSG_LENGTH(msg));
    if ( err <= 0 ) {
      err = SSL_get_error(f->f_dtls_client, err);
      if ( err == SSL_ERROR_WANT_WRITE ) break;
      fprintf(stderr, "flock_send_pconn_responses: ssl error %d\n", err);
      ERR_print_errors_fp(stderr);
      PCONN_UNREF(pc);
      continue;
    } else {
      dbgprintf("flock_send_pconn_responses: sent pconn response\n");
      PCONN_UNREF(pc);
    }
  }
}

static void flock_fn(struct eventloop *el, int op, void *arg) {
  struct qdevent *dns_ev, *tmr_ev;
  struct fdevent *fd_ev;
  struct flock *f;
  struct appstate *as;
  int err;

  switch ( op ) {
  case OP_FLOCK_RESOLVE_NAME:
    dns_ev = (struct qdevent *) arg;
    f = STRUCT_FROM_BASE(struct flock, f_resolver, dns_ev->qde_dnssub);

    if ( pthread_mutex_lock(&f->f_mutex) == 0 ) {
      if ( dnssub_error(&f->f_resolver) == 0 ) {
        int cand_count = 0;
        unsigned int which_cand = 0;
        struct addrinfo *cur_entry;
        for ( cur_entry = dnssub_result(&f->f_resolver); cur_entry; cur_entry = cur_entry->ai_next, cand_count ++);

        dbgprintf("DNS resolution succeeded with %d candidates\n", cand_count);

        if ( !RAND_bytes((unsigned char *)&which_cand, sizeof(which_cand)) ) {
          fprintf(stderr, "Could not choose random candidate: ");
          ERR_print_errors_fp(stderr);
          f->f_flock_state = FLOCK_STATE_NM_NOT_RES;
          dnssub_release(&f->f_resolver);
        } else {
          char cand_addr_buf[INET_ADDRSTRLEN];
          uint16_t old_port = f->f_cur_addr.sin_port;

          which_cand %= cand_count;
          for ( cur_entry = dnssub_result(&f->f_resolver); cur_entry && which_cand != 0; cur_entry = cur_entry->ai_next, which_cand -- );

          assert(cur_entry->ai_family == AF_INET && cur_entry->ai_addrlen >= sizeof(struct sockaddr_in));
          memcpy(&f->f_cur_addr, cur_entry->ai_addr, sizeof(f->f_cur_addr));
          f->f_cur_addr.sin_port = old_port;

          fprintf(stderr, "Using candidate: %s:%d\n",
                  inet_ntop(AF_INET, &f->f_cur_addr.sin_addr, cand_addr_buf, sizeof(cand_addr_buf)),
                  ntohs(f->f_cur_addr.sin_port));

          dnssub_release(&f->f_resolver);

          // Now launch the connection, unless this is a 'STUN-only' flock
          if ( (f->f_flags & FLOCK_FLAG_STUN_ONLY) == 0 )
            flock_start_connection(f, el);
          else if ( f->f_flags & FLOCK_FLAG_PENDING ) {
            f->f_flock_state = FLOCK_STATE_REGISTERED;
            eventloop_queue(el, &f->f_on_should_save);
          }
        }
      } else {
        fprintf(stderr, "Could not resolve flock DNS: %s\n", dnssub_strerror(&f->f_resolver));
        f->f_flock_state = FLOCK_STATE_NM_NOT_RES;
        dnssub_release(&f->f_resolver);
      }
      pthread_mutex_unlock(&f->f_mutex);
    } else
      fprintf(stderr, "Could not handle DNS resolution: mutex locking fails\n");
    break;
  case OP_FLOCK_SOCKET_EVENT:
    fd_ev = (struct fdevent *) arg;
    f = STRUCT_FROM_BASE(struct flock, f_socket_sub, fd_ev->fde_sub);
    as = APPSTATE_FROM_EVENTLOOP(el);

    SAFE_MUTEX_LOCK(&f->f_mutex);
    switch ( f->f_flock_state ) {
    case FLOCK_STATE_CONNECTING:
      fprintf(stderr, "Attempting connection\n");
      // attempt to connect
      err = SSL_do_handshake(f->f_dtls_client);
      if ( err == 0 ) {
        fprintf(stderr, "The flock connection was rejected gracefully\n");
        ERR_print_errors_fp(stderr);

        flock_shutdown_connection(f, el);
        f->f_flock_state = FLOCK_STATE_SUSPENDED;
      } else if ( err < 0 ) {
        if ( flock_handle_ssl_error(f, el, err) < 0 ) {
          fprintf(stderr, "The flock connection is being aborted because of an ssl error\n");
          ERR_print_errors_fp(stderr);

          flock_shutdown_connection(f, el);
          f->f_flock_state = FLOCK_STATE_SUSPENDED;
        }
      } else {
        fprintf(stderr, "The DTLS handshake has been completed\n");

        f->f_flock_state = FLOCK_STATE_SEND_REGISTRATION;
        f->f_retries = 0;

        eventloop_subscribe_fd(el, f->f_socket, FD_SUB_ERROR | FD_SUB_READ | FD_SUB_WRITE,
                               &f->f_socket_sub);
      }
      break;

    case FLOCK_STATE_SUSPENDED:
    case FLOCK_STATE_REGISTERED:
      if ( FD_WRITE_AVAILABLE(fd_ev) ) {
        flock_send_pconn_responses(f);
        dbgprintf("Sent pconn response\n");
      }

      if ( FD_READ_PENDING(fd_ev) ) {
        dbgprintf("Read pending on registered flock socket\n");
        err = flock_receive_request(f, as);
        if ( err < 0 ) {
          fprintf(stderr, "Invalid request\n");
        }
      }

      eventloop_subscribe_fd(el, f->f_socket,
                             FD_SUB_READ | FD_SUB_ERROR |
                             (!(DLIST_EMPTY(&f->f_pconns_with_response)) ? FD_SUB_WRITE : 0),
                             &f->f_socket_sub);
      break;

    case FLOCK_STATE_SEND_REGISTRATION:
    case FLOCK_STATE_REGISTERING:

      if ( FD_WRITE_AVAILABLE(fd_ev) ) {
        if ( f->f_flock_state == FLOCK_STATE_SEND_REGISTRATION )
          flock_send_registration(f, as);

        // Attempt to send out pending connections as well
        flock_send_pconn_responses(f);
      }

      if ( FD_READ_PENDING(fd_ev) ) {
        dbgprintf("Read pending on flock socket\n");
        err = flock_receive_response(f, as, STUN_KITE_REGISTRATION);
        if ( err < 0 ) {
          fprintf(stderr, "Invalid binding response or request\n");
        } else if ( err == STUN_TOO_EARLY ) {
          dbgprintf("Scheduling another registration in %d ms\n",
                    FLOCK_FLAG_TRY_AGAIN_INTERVAL);

          eventloop_cancel_timer(&as->as_eventloop, &f->f_registration_timeout);

          if ( f->f_retries < FLOCK_MAX_RETRIES ) {
            f->f_retries++;
            eventloop_cancel_timer(el, &f->f_refresh_timer);
            timersub_set_from_now(&f->f_refresh_timer, FLOCK_FLAG_TRY_AGAIN_INTERVAL);
            eventloop_subscribe_timer(el, &f->f_refresh_timer);
          } else {
            fprintf(stderr, "No success response from server\n");
            f->f_flags |= FLOCK_FLAG_FAILING | FLOCK_FLAG_CONFLICT;
          }
        } else if ( err == STUN_CONFLICT ) {
          f->f_flags |= FLOCK_FLAG_CONFLICT;
          eventloop_cancel_timer(&as->as_eventloop, &f->f_registration_timeout);
        } else if ( err == 0 ) {
          flock_successful_registration(f, as);
        } else {
          dbgprintf("Invalid error code from flock_receive_response: %d\n", err);
        }
      }

      if ( fd_ev->fde_triggered & FD_SUB_ERROR ) {
        int serr;
        socklen_t errsz = sizeof(serr);
        err = getsockopt(f->f_socket, SOL_SOCKET, SO_ERROR, &serr, &errsz);
        if ( err < 0 ) {
          perror("getsockopt FD_SUB_ERROR");
        } else {
          fprintf(stderr, "ERROR: Got flock socket error: %s\n", strerror(serr));
        }

        f->f_flags |= FLOCK_FLAG_FAILING;
        if ( f->f_retries >= FLOCK_MAX_RETRIES ) {
          fprintf(stderr, "Reached max retries for flock. Setting disabled\n");
          f->f_retries = 0;
          f->f_flock_state = FLOCK_STATE_CONNECTING;
          f->f_flags &= ~FLOCK_FLAG_REGISTRATION_VALID;
        } else
          f->f_retries ++;
      }

      eventloop_subscribe_fd(el, f->f_socket,
                             FD_SUB_READ | FD_SUB_ERROR |
                             ((!DLIST_EMPTY(&f->f_pconns_with_response)) ? FD_SUB_WRITE : 0),
                             &f->f_socket_sub);

      break;

    default:
      dbgprintf("flock_fn: Got socket event in state %d\n", f->f_flock_state);
    }
    pthread_mutex_unlock(&f->f_mutex);

    break;

  case OP_FLOCK_REGISTRATION_TIMEOUT:
    tmr_ev = (struct qdevent *) arg;
    f = STRUCT_FROM_BASE(struct flock, f_registration_timeout, tmr_ev->qde_timersub);
    FLOCK_NEXT_RETRY(f, el);

    dbgprintf("Reg timeout\n");
    eventloop_subscribe_fd(el, f->f_socket, FD_SUB_READ | FD_SUB_WRITE | FD_SUB_ERROR, &f->f_socket_sub);
    break;

  case OP_FLOCK_REFRESH:
    tmr_ev = (struct qdevent *) arg;
    f = STRUCT_FROM_BASE(struct flock, f_refresh_timer, tmr_ev->qde_timersub);
    flock_refresh_registration(f); // Updates the transaction id

    SAFE_MUTEX_LOCK(&f->f_mutex);
    f->f_flock_state = FLOCK_STATE_SEND_REGISTRATION;
    pthread_mutex_unlock(&f->f_mutex);

    dbgprintf("Refresh timer\n");
    eventloop_subscribe_fd(el, f->f_socket, FD_SUB_WRITE | FD_SUB_ERROR, &f->f_socket_sub);
    break;

  default:
    fprintf(stderr, "flock_fn: Unknown op %d\n", op);
  }
}

static void flock_successful_registration(struct flock *f, struct appstate *as) {

  fprintf(stderr, "The flock has been successfully registered\n");

  if ( f->f_flags & FLOCK_FLAG_PENDING )
    eventloop_queue(&as->as_eventloop, &f->f_on_should_save);

  f->f_flock_state = FLOCK_STATE_REGISTERED;

  // Stop the registration timeout
  eventloop_cancel_timer(&as->as_eventloop, &f->f_registration_timeout);
  f->f_retries = 0;
  f->f_flags &= ~(FLOCK_FLAG_FAILING | FLOCK_FLAG_PENDING | FLOCK_FLAG_CONFLICT);
  f->f_flags |= FLOCK_FLAG_REGISTRATION_VALID;

  // Start the refresh timer
  eventloop_cancel_timer(&as->as_eventloop, &f->f_refresh_timer);
  timersub_set_from_now(&f->f_refresh_timer, FLOCK_SEND_REGISTRATION_INTERVAL);
  eventloop_subscribe_timer(&as->as_eventloop, &f->f_refresh_timer);
}

void flock_start_service(struct flock *f, struct eventloop *el) {
  if ( pthread_mutex_lock(&f->f_mutex) == 0 ) {
    int err = 0;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_flags = AI_ADDRCONFIG | AI_V4MAPPED | AI_NUMERICSERV;

    if ( (f->f_flags & FLOCK_FLAG_STUN_ONLY) == 0 )
      f->f_flock_state = FLOCK_STATE_PENDING;

    dnssub_init(&f->f_resolver, OP_FLOCK_RESOLVE_NAME, flock_fn);

    err = dnssub_start_resolution(&f->f_resolver, el, f->f_hostname, "0",
                                  DNSSUB_FLAG_FREE_NODE, &hints);
    if ( err < 0 ) {
      fprintf(stderr, "dnssub_start_resolution: failed\n");
      f->f_flock_state = FLOCK_STATE_NM_NOT_RES;
      dnssub_release(&f->f_resolver);
      goto error;
    }

  error:
    pthread_mutex_unlock(&f->f_mutex);
  } else
    fprintf(stderr, "flock_start_service: pthread_mutex_lock(&f->f_mutex) failed\n");
}

static void flock_start_connection(struct flock *f, struct eventloop *el) {
  struct appstate *as = APPSTATE_FROM_EVENTLOOP(el);
  BIO *sock_bio = NULL;
  int err;

  f->f_flock_state = FLOCK_STATE_CONNECTING;
  f->f_socket = 0;
  f->f_dtls_client = NULL;
  f->f_retries = 0;
  fdsub_clear(&f->f_socket_sub);

  err = socket(AF_INET, SOCK_DGRAM, 0);
  if ( err < 0 ) {
    perror("flock_start_connection: socket");
    return;
  }
  f->f_socket = err;

  fdsub_init(&f->f_socket_sub, el, f->f_socket, OP_FLOCK_SOCKET_EVENT, flock_fn);
  timersub_init_default(&f->f_registration_timeout, OP_FLOCK_REGISTRATION_TIMEOUT, flock_fn);
  timersub_init_default(&f->f_refresh_timer, OP_FLOCK_REFRESH, flock_fn);

  err = set_socket_nonblocking(f->f_socket);
  if ( err < 0 ) {
    perror("flock_start_connection: set_socket_nonblocking");
    goto error;
  }

  err = connect(f->f_socket, (struct sockaddr *)&f->f_cur_addr, sizeof(f->f_cur_addr));
  if ( err < 0 ) {
    perror("flock_start_connection: connect");
    goto error;
  }

  fprintf(stderr, "Connected to flock\n");

  flock_refresh_registration(f);

  if ( (f->f_flags & FLOCK_FLAG_INSECURE) == 0 ) {
    f->f_dtls_client = SSL_new(as->as_dtls_ctx);
    if ( !f->f_dtls_client ) {
      fprintf(stderr, "flock_start_connection: SSL_new fails\n");
      goto openssl_error;
    }

    if ( !SSL_set_flock(f->f_dtls_client, f) ) {
      fprintf(stderr, "flock_start_connection: SSL_set_flock fails\n");
      goto openssl_error;
    }

    SSL_set_connect_state(f->f_dtls_client);
    SSL_set_mode(f->f_dtls_client, SSL_MODE_AUTO_RETRY);

    sock_bio = BIO_new_dgram(f->f_socket, BIO_NOCLOSE);
    if ( !sock_bio ) {
      fprintf(stderr, "flock_start_connection: BIO_new_fd fails\n");
      goto openssl_error;
    }

    // Set the bio to use the address
    if( !BIO_ctrl(sock_bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &f->f_cur_addr) )
      fprintf(stderr, "flock_start_connection: Could not set connected address\n");

    SSL_set_bio(f->f_dtls_client, sock_bio, sock_bio);
    sock_bio = NULL;
  } else
    f->f_flock_state = FLOCK_STATE_SEND_REGISTRATION;

  // write and error for registration events
  dbgprintf("Start send\n");
  eventloop_subscribe_fd(el, f->f_socket, FD_SUB_READ | FD_SUB_WRITE | FD_SUB_ERROR, &f->f_socket_sub);

  return;

  openssl_error:
    ERR_print_errors_fp(stderr);
 error:
  if ( f->f_socket ) {
    close(f->f_socket);
    f->f_socket = 0;
  }

  if ( f->f_dtls_client ) {
    SSL_free(f->f_dtls_client);
    f->f_dtls_client = NULL;
  }

  if ( sock_bio ) BIO_free(sock_bio);

  f->f_flock_state = FLOCK_STATE_SUSPENDED;
}

void flock_pconn_expires(struct flock *f, struct pconn *pc) {
  struct pconn *existing;
  fprintf(stderr, "flock_fn: TODO Expiring pending connection %08lx\n", pc->pc_conn_id);
  HASH_FIND(pc_hh, f->f_pconns, &pc->pc_conn_id, sizeof(pc->pc_conn_id), existing);
  if ( existing ) {
    HASH_DELETE(pc_hh, f->f_pconns, pc);
  }
  PCONN_UNREF(pc);
}

void flock_request_pconn_write_unlocked(struct flock *f, struct pconn *pc) {
  if ( !DLIST_ENTRY_IN_LIST(&f->f_pconns_with_response,
                            pc_pconns_with_response_dl,
                            pc) ) { // Only one write per pconn allowed
    PCONN_REF(pc);
    DLIST_INSERT(&f->f_pconns_with_response, pc_pconns_with_response_dl, pc);
    dbgprintf("Request pconn write\n");
    eventloop_subscribe_fd(&pc->pc_appstate->as_eventloop, f->f_socket, FD_SUB_WRITE,
                           &f->f_socket_sub);
  }
}

void flock_request_pconn_write(struct flock *f, struct pconn *pc) {
  SAFE_MUTEX_LOCK(&f->f_mutex);
  SAFE_MUTEX_LOCK(&pc->pc_mutex);
  flock_request_pconn_write_unlocked(f, pc);
  pthread_mutex_unlock(&pc->pc_mutex);
  pthread_mutex_unlock(&f->f_mutex);
}
