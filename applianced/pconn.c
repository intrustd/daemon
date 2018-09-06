#include <openssl/rand.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>

#include "pconn.h"
#include "flock.h"
#include "state.h"

// A candidate source. This information is taken from the full set of
// flocks when the pconn is started
struct candsrc {
  // The address to use to connect to the candidates source
  struct sockaddr cs_svr;

  // The pconn to report candidates to
  struct pconn   *cs_pconn;

  uint32_t        cs_flags;

  struct timersub cs_retransmit;

  struct stuntxid cs_tx_id;

  int             cs_state;
  int             cs_retries;
};

// Do not assume the remote server can handle Kite requests
#define CS_FLAG_STUN_ONLY  0x1
// Do not use DTLS for connecting
#define CS_FLAG_INSECURE   0x2
// Attempt to create a TURN tunnel if necessary
#define CS_FLAG_TURN       0x4

// We have errored out
#define CS_STATE_ERROR          (-1)
#define CS_STATE_INITIAL         0
// For secure connections, we are in the process of running SSL_connect
#define CS_STATE_DTLS_CONNECTING 1
// For insecure or secure connections, we are in the process of sending binding requests
#define CS_STATE_BINDING         2
// We have completed all candidate collection on this source
#define CS_STATE_DONE            3

#define CS_RETRANSMIT_INTERVAL 100
#define CS_MAX_RETRIES         7

#define OP_PCONN_EXPIRES EVT_CTL_CUSTOM
#define OP_PCONN_STARTS (EVT_CTL_CUSTOM + 1)
#define OP_PCONN_SOCKET (EVT_CTL_CUSTOM + 2)
#define OP_PCONN_CANDSRC_RETRANSMIT (EVT_CTL_CUSTOM + 3)

static void pconn_fn(struct eventloop *el, int op, void *arg);
static void pconn_free(struct pconn *pc);

static void pconn_state_may_change(struct pconn *pc);

static int candsrc_jitter() {
  int r;
  if ( !RAND_bytes((unsigned char *)&r, sizeof(r)) ) r = 100;

  return r % PCONN_CANDSRC_JITTER;
}

static void candsrc_release(struct candsrc *src) {
  assert( eventloop_cancel_timer(&src->cs_pconn->pc_appstate->as_eventloop, &src->cs_retransmit) == 0 );
}

static void candsrc_transmit_binding(struct candsrc *src) {
  struct stunmsg msg;
  struct stunattr *attr;
  int err;

  STUN_INIT_MSG(&msg, STUN_BINDING);
  memcpy(&msg.sm_tx_id, &src->cs_tx_id, sizeof(msg.sm_tx_id));
  attr = STUN_FIRSTATTR(&msg);

  err = stun_add_mapped_address_attrs(&attr, &msg, sizeof(msg),
                                      &src->cs_svr, sizeof(src->cs_svr));
  assert(err == 0);

  STUN_FINISH_WITH_FINGERPRINT(attr, &msg, sizeof(msg), err);
  assert(err == 0);

  if ( src->cs_flags & CS_FLAG_INSECURE ) {
    err = sendto(src->cs_pconn->pc_socket, &msg, STUN_MSG_LENGTH(&msg), 0,
                 &src->cs_svr, sizeof(src->cs_svr));
    if ( err < 0 ) {
      if ( errno == EWOULDBLOCK ) {
        fprintf(stderr, "candsrc_transmit_binding: could not retransmit, because there's no space in the buffer\n");
      } else
        fprintf(stderr, "candsrc_transmit_binding: waiting for response\n");
    }
  } else {
    fprintf(stderr, "candsrc_transmit_binding: TODO send STUNS requests\n");
  }
}

static void candsrc_retransmit(struct candsrc *src) {
  switch ( src->cs_state ) {
  case CS_STATE_DTLS_CONNECTING:
    fprintf(stderr, "TODO: candsrc_retransmit: should connect via DTLS\n");
    break;
  case CS_STATE_BINDING:
    src->cs_retries++;
    if ( src->cs_retries >= CS_MAX_RETRIES ) {
      src->cs_state = CS_STATE_ERROR;
      fprintf(stderr, "candsrc_retransmit: candidate source errored... no response after %d retries\n", src->cs_retries);
      pconn_state_may_change(src->cs_pconn);
    } else {
      if ( src->cs_flags & CS_FLAG_TURN )
        fprintf(stderr, "candsrc_retransmit: send TURN requests\n");
      else
        candsrc_transmit_binding(src);

      timersub_set_from_now(&src->cs_retransmit,
                            candsrc_jitter() + (CS_RETRANSMIT_INTERVAL << src->cs_retries));
      PCONN_WREF(src->cs_pconn);
      eventloop_subscribe_timer(&src->cs_pconn->pc_appstate->as_eventloop, &src->cs_retransmit);
      fprintf(stderr, "TODO: candsrc_retransmit: binding\n");
    }
    break;
  case CS_STATE_ERROR:
  case CS_STATE_DONE:
  default:
    break;
  }
}

static void pconn_delayed_start(struct pconn *pc) {
  struct appstate *app = pc->pc_appstate;
  struct flock *cur_flock, *tmp_flock;

  fprintf(stderr, "pconn_delayed_start: start\n");
  pc->pc_ice_gathering_state = PCONN_ICE_GATHERING_STATE_GATHERING;
  // Collect all flocks and personas
  assert( pthread_rwlock_rdlock(&app->as_flocks_mutex) == 0 );
  // For each flock, make a new candsrc
  pc->pc_candidate_sources = malloc(sizeof(pc->pc_candidate_sources[0]) *
                                    HASH_CNT(f_hh, app->as_flocks));
  if ( pc->pc_candidate_sources ) {
    HASH_ITER(f_hh, app->as_flocks, cur_flock, tmp_flock) {
      struct candsrc *cursrc = &pc->pc_candidate_sources[pc->pc_candidate_sources_count];
      if (cur_flock->f_flags & FLOCK_FLAG_KITE_ONLY) continue;

      if ( pthread_mutex_lock(&cur_flock->f_mutex) == 0 ) {
        pc->pc_candidate_sources_count++;

        memcpy(&cursrc->cs_svr, &cur_flock->f_cur_addr, sizeof(cur_flock->f_cur_addr));
        cursrc->cs_pconn = pc;
        cursrc->cs_flags = 0;
        cursrc->cs_retries = 0;
        cursrc->cs_state = CS_STATE_INITIAL;

        if ( cur_flock->f_flags & FLOCK_FLAG_STUN_ONLY )
          cursrc->cs_flags |= CS_FLAG_STUN_ONLY;
        if ( cur_flock->f_flags & FLOCK_FLAG_INSECURE )
          cursrc->cs_flags |= CS_FLAG_INSECURE;

        if ( cursrc->cs_flags & CS_FLAG_INSECURE )
          cursrc->cs_state= CS_STATE_BINDING;

        stun_random_tx_id(&cursrc->cs_tx_id);

        // The source should start transmitting at some point
        PCONN_WREF(pc);
        timersub_init_from_now(&cursrc->cs_retransmit, candsrc_jitter(),
                               OP_PCONN_CANDSRC_RETRANSMIT, pconn_fn);
        eventloop_subscribe_timer(&app->as_eventloop, &cursrc->cs_retransmit);

        pthread_mutex_unlock(&cur_flock->f_mutex);
      } else
        fprintf(stderr, "pconn_delayed_start: couldn't lock flock mutex\n");
    }
  } else
    fprintf(stderr, "pconn_delayed_start: out of memory to store flocks\n");
  pthread_rwlock_unlock(&app->as_flocks_mutex);

  fprintf(stderr, "pconn_delayed_start: finished\n");

  FDSUB_SUBSCRIBE(&pc->pc_socket_sub, FD_SUB_READ | FD_SUB_ERROR);
  eventloop_subscribe_fd(&pc->pc_appstate->as_eventloop,
                         pc->pc_socket,
                         &pc->pc_socket_sub);
}

static void pconn_fn(struct eventloop *el, int op, void *arg) {
  struct qdevent *evt = (struct qdevent *) arg;
  struct pconn *pc;
  struct candsrc *cs;

  switch ( op ) {
  case OP_PCONN_EXPIRES:
    pc = STRUCT_FROM_BASE(struct pconn, pc_timeout, evt->qde_sub);
    flock_pconn_expires(pc->pc_flock, pc);
    break;
  case OP_PCONN_STARTS:
    pc = STRUCT_FROM_BASE(struct pconn, pc_start_evt, evt->qde_sub);
    if ( PCONN_LOCK(pc) == 0 ) {
      fprintf(stderr, "pconn_fn: Starting... %p %d\n", pc, pc->pc_state);
      pconn_delayed_start(pc);
      PCONN_UNREF(pc);
    } else
      fprintf(stderr, "pconn_fn: Pconn destroyed before OP_PCONN_STARTS\n");
    break;
  case OP_PCONN_CANDSRC_RETRANSMIT:
    cs = STRUCT_FROM_BASE(struct candsrc, cs_retransmit, evt->qde_sub);
    pc = cs->cs_pconn;
    if ( PCONN_LOCK(pc) == 0 ) {
      candsrc_retransmit(cs);
      PCONN_UNREF(pc);
    }
    break;
  case OP_PCONN_SOCKET:
    break;
  default:
    fprintf(stderr, "pconn_fn: Unknown op %d\n", op);
  }
}

static void pconn_free_fn(const struct shared *s, int level) {
  struct pconn *pc = STRUCT_FROM_BASE(struct pconn, pc_shared, s);
  if ( level != SHFREE_NO_MORE_REFS ) return;

  pconn_free(pc);
}

struct pconn *pconn_alloc(uint64_t conn_id, struct flock *f, struct appstate *as, int type) {
  int err;
  struct pconn *ret = malloc(sizeof(struct pconn));
  if ( !ret ) return NULL;

  fprintf(stderr, "New pconn %p\n", ret);

  SHARED_INIT(&ret->pc_shared, pconn_free_fn);

  if ( pthread_mutex_init(&ret->pc_mutex, NULL) != 0 ) {
    free(ret);
    return NULL;
  };

  stun_random_tx_id(&ret->pc_tx_id);
  ret->pc_last_req = STUN_KITE_STARTCONN;
  ret->pc_sctp_port = 6000; // TODO

  // Generate user fragment and password
  if ( !random_printable_string(ret->pc_our_ufrag, sizeof(ret->pc_our_ufrag)) ||
       !random_printable_string(ret->pc_our_pwd, sizeof(ret->pc_our_pwd)) ) {
    fprintf(stderr, "pconn_alloc: could not generate ICE parameters\n");
    pthread_mutex_destroy(&ret->pc_mutex);
    free(ret);
    return NULL;
  }

  // TODO IPv6 / TCP transport for STUN requests
  ret->pc_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if ( ret->pc_socket < 0 ) {
    perror("pconn_alloc: socket");
    pthread_mutex_destroy(&ret->pc_mutex);
    free(ret);
    return NULL;
  }

  fdsub_init(&ret->pc_socket_sub, &as->as_eventloop, ret->pc_socket, OP_PCONN_SOCKET, pconn_fn);

  ret->pc_appstate = as;
  ret->pc_flock = f;
  ret->pc_conn_id = conn_id;
  ret->pc_candidate_sources = NULL;
  ret->pc_candidate_sources_count = 0;
  ret->pc_type = type;
  ret->pc_state = PCONN_STATE_WAIT_FOR_LOGIN;
  ret->pc_ice_gathering_state = PCONN_ICE_GATHERING_STATE_NEW;
  ret->pc_auth_attempts = 0;
  ret->pc_personaset = NULL;
  ret->pc_persona = NULL;

  DLIST_ENTRY_CLEAR(&ret->pc_pconns_with_response_dl);

  // Collect all personas
  err = appstate_get_personaset(as, &ret->pc_personaset);
  if ( err < 0 ) {
    fprintf(stderr, "pconn_alloc: could not get personaset\n");
  }

  timersub_init_from_now(&ret->pc_timeout, PCONN_TIMEOUT, OP_PCONN_EXPIRES, pconn_fn);
  qdevtsub_init(&ret->pc_start_evt, OP_PCONN_STARTS, pconn_fn);

  return ret;
}

static void pconn_free(struct pconn *pc) {
  int i;

  assert( pthread_mutex_lock(&pc->pc_mutex) == 0 );

  if ( pc->pc_socket ) {
    close(pc->pc_socket);
    pc->pc_socket = 0;
  }

  if ( pc->pc_personaset ) {
    PERSONASET_UNREF(pc->pc_personaset);
    pc->pc_personaset = NULL;
  }

  if ( pc->pc_persona ) {
    PERSONA_UNREF(pc->pc_persona);
    pc->pc_persona = NULL;
  }

  if ( pc->pc_candidate_sources ) {
    for ( i = 0; i < pc->pc_candidate_sources_count; ++i ) {
      candsrc_release(&pc->pc_candidate_sources[i]);
    }
    free(pc->pc_candidate_sources);
    pc->pc_candidate_sources = NULL;
  }

  pthread_mutex_unlock(&pc->pc_mutex);

  pthread_mutex_destroy(&pc->pc_mutex);
  free(pc);
}

void pconn_set_request(struct pconn *pc, uint16_t req, const struct stuntxid *id) {
  assert( pthread_mutex_lock(&pc->pc_mutex) == 0 );
  memcpy(&pc->pc_tx_id, id, sizeof(pc->pc_tx_id));
  pc->pc_last_req = req;
  pthread_mutex_unlock(&pc->pc_mutex);
}

void pconn_start_service(struct pconn *pc) {
  fprintf(stderr, "start pconn %d\n", pc->pc_state);
  PCONN_WREF(pc);
  eventloop_subscribe_timer(&pc->pc_appstate->as_eventloop, &pc->pc_timeout);

  PCONN_WREF(pc);
  eventloop_queue(&pc->pc_appstate->as_eventloop, &pc->pc_start_evt);
}

#define OFFER_LINE_START if (1) {                                       \
    struct stunattr* next_attr;                                         \
    line_off = 0;                                                       \
    next_attr = STUN_NEXTATTR(*attr);                                   \
    if ( !STUN_IS_VALID(next_attr, msg, buf_sz) ) break;                \
    STUN_INIT_ATTR(next_attr, STUN_ATTR_FINGERPRINT, 4);                \
    if ( !STUN_ATTR_IS_VALID(next_attr, msg, buf_sz) ) break;           \
    *attr = next_attr;                                                  \
  }
#define OFFER_WRITE(...) if (1) {                                       \
    err = snprintf(line + line_off, sizeof(line) - line_off,            \
                   __VA_ARGS__);                                        \
    if ( err >= (sizeof(line) - line_off) ) {                           \
      ret = -1;                                                         \
      fprintf(stderr, "pconn_write_offer: no more space in line\n");    \
      break;                                                            \
    }                                                                   \
    line_off += err;                                                    \
  }
#define OFFER_LINE_END if(1) {                                          \
    STUN_INIT_ATTR(*attr, STUN_ATTR_KITE_SDP_LINE, sizeof(uint16_t) + line_off); \
    if ( !STUN_ATTR_IS_VALID(*attr, msg, buf_sz) ) break;               \
    ret = 0;                                                            \
    *((uint16_t *) STUN_ATTR_DATA(*attr)) = htons(pc->pc_offer_line);   \
    memcpy(((char *) STUN_ATTR_DATA(*attr)) + sizeof(uint16_t), line, line_off); \
    if ( pc->pc_offer_line >= 0 ) pc->pc_offer_line ++;                 \
  }
#define OFFER_LINE(...) if (1) {                \
    OFFER_LINE_START;                           \
    OFFER_WRITE(__VA_ARGS__);                   \
    OFFER_LINE_END;                             \
  }

int pconn_write_offer(struct pconn *pc, struct stunmsg *msg,
                      struct stunattr **attr, size_t buf_sz) {
  char line[1024], addr_buf[INET6_ADDRSTRLEN + 1];
  struct sockaddr addr;
  char *addrty;
  int ret = -1, err, line_off = 0, i;
  socklen_t addrsz = sizeof(addr);
  X509 *cert;
  BIO *md_bio;
  unsigned char digest[SHA256_DIGEST_LENGTH];

  err = getsockname(pc->pc_socket, &addr, &addrsz);
  if ( err < 0 ) {
    perror("pconn_write_offer: getsockname");
    addr.sa_family = AF_UNSPEC;
  }

  switch ( addr.sa_family ) {
  case AF_INET:
    addrty = "IP4";
    inet_ntop(AF_INET, &((struct sockaddr_in *)&addr)->sin_addr, addr_buf, sizeof(addr_buf));
    break;
  case AF_INET6:
    addrty = "IP6";
    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&addr)->sin6_addr, addr_buf, sizeof(addr_buf));
    break;
  default:
    addrty = "IP";
    strncpy(addr_buf, "127.0.0.1", sizeof(addr_buf));
    break;
  }

  switch ( pc->pc_offer_line ) {
  case 0: OFFER_LINE("v=0");
  case 1:
    OFFER_LINE("o=- %lu 2 IN %s %s", pc->pc_conn_id, addrty, addr_buf)
  case 2:
    OFFER_LINE("s=-");
  case 3:
    OFFER_LINE("t=0 0");
  case 4:
    OFFER_LINE("a=group:BUNDLE data");
  case 5:
    OFFER_LINE("a=msid-semantic: WMS");
  case 6:
    OFFER_LINE("m=application 9 DTLS/SCTP webrtc-datachannel");
  case 7:
    OFFER_LINE("a=max-message-size:%d", PCONN_MAX_MESSAGE_SIZE);
  case 8:
    OFFER_LINE("a=sctpmap:%d webrtc-datachannel %d", pc->pc_sctp_port, PCONN_MAX_SCTP_STREAMS);
  case 9:
    OFFER_LINE("a=ice-options:trickle");
  case 10:
    OFFER_LINE("a=setup:actpass"); // TODO allow actpass
  case 11:
    OFFER_LINE("a=mid:data");
  case 12:
    OFFER_LINE("a=ice-ufrag:%.*s", (int) sizeof(pc->pc_our_ufrag), pc->pc_our_ufrag);
  case 13:
    OFFER_LINE("a=ice-pwd:%.*s", (int) sizeof(pc->pc_our_pwd), pc->pc_our_pwd);
  case 14:
    OFFER_LINE_START;
    cert = appstate_get_certificate(pc->pc_appstate);
    if ( !cert ) return -1;

    md_bio = BIO_new(BIO_f_md());
    if ( !md_bio ) {
      X509_free(cert);
      return -1;
    }

    BIO_set_md(md_bio, EVP_sha256());
    err = i2d_X509_bio(md_bio, cert);
    if ( err < 0 ) {
      X509_free(cert);
      BIO_free(md_bio);
      return -1;
    }

    err = BIO_gets(md_bio, (char *) digest, sizeof(digest));
    if ( err != sizeof(digest) ) {
      X509_free(cert);
      BIO_free(md_bio);
      return -1;
    }

    OFFER_WRITE("a=fingerprint:sha-256");
    for ( i = 0; i < sizeof(digest); ++i )
      OFFER_WRITE("%c%02x", i == 0 ? ' ' : ':',
                  digest[i]);

    X509_free(cert);
    BIO_free(md_bio);
    OFFER_LINE_END;
  default:
    pc->pc_offer_line = -1; // Mark done
    OFFER_LINE_START;
    OFFER_LINE_END;
  };

  return ret;
}

#define STUN_ADD_CONNECTION_ID                                          \
  do {                                                                  \
    if ( !STUN_IS_VALID(attr, msg, buf_sz) ) return -1;                 \
    STUN_INIT_ATTR(attr, STUN_ATTR_KITE_CONN_ID, sizeof(pc->pc_conn_id)); \
    if ( !STUN_ATTR_IS_VALID(attr, msg, buf_sz) ) return -1;            \
    *((uint64_t *) STUN_ATTR_DATA(attr)) = htonll(pc->pc_conn_id);      \
  } while (0)

int pconn_write_response(struct pconn *pc, char *buf, int buf_sz) {
  int ret = 0;
  struct stunmsg *msg = (struct stunmsg *) buf;
  struct stunattr *attr = STUN_FIRSTATTR(msg);

  fprintf(stderr, "pconn_write_response %d\n", pc->pc_state);
  fprintf(stderr, "pconn_write_response: tx %08x%08x%08x\n", pc->pc_tx_id.a, pc->pc_tx_id.b, pc->pc_tx_id.c);

  switch ( pc->pc_state ) {
  case PCONN_STATE_WAIT_FOR_LOGIN:
  case PCONN_STATE_START_OFFER:
    STUN_INIT_MSG(msg, STUN_RESPONSE | STUN_KITE_STARTCONN);
    memcpy(&msg->sm_tx_id, &pc->pc_tx_id, sizeof(msg->sm_tx_id));

    STUN_ADD_CONNECTION_ID;

    if ( pc->pc_personaset ) {
      fprintf(stderr, "pconn_respond: adding personas hash\n");
      attr = STUN_NEXTATTR(attr);
      if ( !STUN_IS_VALID(attr, msg, buf_sz) ) return -1;
      STUN_INIT_ATTR(attr, STUN_ATTR_KITE_PERSONAS_HASH, SHA256_DIGEST_LENGTH);
      if ( !STUN_ATTR_IS_VALID(attr, msg, buf_sz) ) return -1;
      memcpy((char *) STUN_ATTR_DATA(attr), pc->pc_personaset->ps_hash, SHA256_DIGEST_LENGTH);
    }

    STUN_FINISH_WITH_FINGERPRINT(attr, msg, buf_sz, ret);
    fprintf(stderr, "pconn_respond: %d\n", ret);
    break;

  case PCONN_STATE_SENDING_OFFER:
    fprintf(stderr, "pconn_respond: sending offer\n");
    // We've successfully sent the connection start the offer
    STUN_INIT_MSG(msg, STUN_RESPONSE | STUN_KITE_SENDOFFER);
    memcpy(&msg->sm_tx_id, &pc->pc_tx_id, sizeof(msg->sm_tx_id));
    STUN_ADD_CONNECTION_ID;

    if ( pconn_write_offer(pc, msg, &attr, buf_sz) < 0 )
      ret = -1;
    else {
      STUN_FINISH_WITH_FINGERPRINT(attr, msg, buf_sz, ret);
      assert(ret == 0);
    }

    break;

  default:
    STUN_INIT_MSG(msg, STUN_RESPONSE | STUN_ERROR | pc->pc_last_req);
    memcpy(&msg->sm_tx_id, &pc->pc_tx_id, sizeof(msg->sm_tx_id));
    if ( !STUN_IS_VALID(attr, msg, buf_sz) ) return -1;
    STUN_INIT_ATTR(attr, STUN_ATTR_ERROR_CODE, sizeof(uint16_t));
    if ( !STUN_ATTR_IS_VALID(attr, msg, buf_sz) ) return -1;
    switch ( pc->pc_state ) {
    case PCONN_STATE_ERROR_AUTH_FAILED:
      if ( pc->pc_auth_attempts >= PCONN_MAX_AUTH_ATTEMPTS ) {
        *((uint16_t *) STUN_ATTR_DATA(attr)) = ntohs(STUN_BAD_REQUEST);
      } else {
        *((uint16_t *) STUN_ATTR_DATA(attr)) = ntohs(STUN_UNAUTHORIZED);
      }
      break;
    default:
      *((uint16_t *) STUN_ATTR_DATA(attr)) = ntohs(STUN_SERVER_ERROR);
      break;
    }

    attr = STUN_NEXTATTR(attr);
    STUN_ADD_CONNECTION_ID;

    STUN_FINISH_WITH_FINGERPRINT(attr, msg, buf_sz, ret);
    break;
  }

  return ret;
}

void pconn_finish(struct pconn *pc) {
  if ( eventloop_cancel_timer(&pc->pc_appstate->as_eventloop, &pc->pc_timeout) )
    PCONN_WUNREF(pc);

  flock_pconn_expires(pc->pc_flock, pc);
}

static void pconn_auth_fails(struct pconn *pc) {
  if ( !PCONN_IS_ERRORED(pc) ) {
    pc->pc_state = PCONN_STATE_ERROR_AUTH_FAILED;
    pc->pc_auth_attempts ++;

    if ( pc->pc_auth_attempts >= PCONN_MAX_AUTH_ATTEMPTS)
      pconn_finish(pc);
  }
}

void pconn_recv_sendoffer(struct pconn *pc, int line) {
  PCONN_REF(pc);
  assert( pthread_mutex_lock(&pc->pc_mutex) == 0 );

  fprintf(stderr, "pconn_recv_sendoffer: for line %d in state %d\n", line, pc->pc_state);
  if ( pc->pc_state == PCONN_STATE_START_OFFER )
    pc->pc_state = PCONN_STATE_SENDING_OFFER;

  if ( line >= pc->pc_offer_line ) {
    pc->pc_offer_line = line;

    fprintf(stderr, "pconn_recv_sendoffer: Requesting write\n");
    flock_request_pconn_write_unlocked(pc->pc_flock, pc);
  }

  pthread_mutex_unlock(&pc->pc_mutex);
  PCONN_UNREF(pc);
}

void pconn_recv_startconn(struct pconn *pc, const char *persona_id,
                          const char *credential, size_t cred_sz) {
  PCONN_REF(pc);
  assert( pthread_mutex_lock(&pc->pc_mutex) == 0);

  if ( persona_id &&
       PCONN_CAN_AUTH(pc) ) {
    struct persona *p;

    // Attempt to find this persona
    if ( pc->pc_persona ) {
      // If we already have a persona, ensure that the ids match
      p = pc->pc_persona;
    } else {
      // Find the persona in the hash table
      appstate_lookup_persona(pc->pc_appstate, persona_id, &p);
    }

    // Ensure the IDs match (not useful for looking up in hash table,
    // but necessary for an already established persona).
    if ( p ) {
      if ( memcmp(p->p_persona_id, persona_id, PERSONA_ID_LENGTH) != 0 ) {
        pc->pc_persona = NULL;
        PERSONA_UNREF(p);
        pconn_auth_fails(pc);
      } else {
        // Ensure the persona credential validates
        if ( persona_credential_validates(p, credential, cred_sz) != 1 ) {
          pc->pc_persona = NULL;
          PERSONA_UNREF(p);
          pconn_auth_fails(pc);
        } else {
          pc->pc_state = PCONN_STATE_START_OFFER;
          pc->pc_persona = p;
        }
      }
    } else {
      pconn_auth_fails(pc);
    }
  }

  flock_request_pconn_write_unlocked(pc->pc_flock, pc);
  pthread_mutex_unlock(&pc->pc_mutex);
  PCONN_UNREF(pc);
}

static void pconn_ice_state_changes(struct pconn *pc) {
  if ( pc->pc_ice_gathering_state == PCONN_ICE_GATHERING_STATE_ERROR )
    pc->pc_state = PCONN_STATE_ICE_GATHERING_ERROR;
}

static void pconn_state_may_change(struct pconn *pc) {
  int i, all_done = 1, any_successful = 0;
  int old_state = pc->pc_ice_gathering_state, new_state = PCONN_ICE_GATHERING_STATE_GATHERING;

  for ( i = 0; i < pc->pc_state; ++i ) {
    struct candsrc *cs = &pc->pc_candidate_sources[i];
    if ( cs->cs_state != CS_STATE_DONE )
      all_done = 0;

    if ( cs->cs_state != CS_STATE_ERROR )
      any_successful = 1;
  }

  if ( all_done )
    new_state = PCONN_ICE_GATHERING_STATE_COMPLETE;

  if ( !any_successful )
    new_state = PCONN_ICE_GATHERING_STATE_ERROR;

  if ( new_state != old_state ) {
    pc->pc_state = new_state;
    pconn_ice_state_changes(pc);
  }
}
