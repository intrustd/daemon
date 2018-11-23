#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <assert.h>

#include "pconn.h"
#include "flock.h"
#include "state.h"
#include "token.h"

#define DEFAULT_SCTP_PORT 5000

// According to https://tools.ietf.org/id/draft-ietf-tls-dtls13-02.html#rfc.section.4.1.1,
// DTLS packets start with 21, 22, 23 or 25
#define IS_DTLS_PACKET(c) ((c) == 21 || (c) == 22 || (c) == 23 || (c) == 25)

// A candidate source. This information is taken from the full set of
// flocks when the pconn is started
struct candsrc {
  // The address to use to connect to the candidates source
  kite_sock_addr  cs_svr;

  // The local address (valid if sa_family != AF_UNSPEC)
  kite_sock_addr  cs_local_addr;

  // The pconn to report candidates to
  struct pconn   *cs_pconn;

  uint32_t        cs_flags;

  struct timersub cs_retransmit;

  struct stuntxid cs_tx_id;

  // Because of the necessity of using connect() even over UDP
  // sockets, each candsrc needs its own port
  int             cs_socket;
  struct fdsub    cs_socket_sub;

  int             cs_state;
  int             cs_retries;
  int             cs_host_candidate_added : 1;

  // If this is >= 0, it means we should send a connectivity check to
  // the remote candidate specificed
  struct icecandpair *cs_scheduled_connectivity_check;
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
// We have received a binding response, but per the ICE RFC, we are
// continuing to send KEEP ALIVE requests on this source
#define CS_STATE_KEEPALIVE       4

#define CS_RETRANSMIT_INTERVAL 400
#define CS_MAX_RETRIES         7

#define FORMAT_ICE_CANDIDATE(cand, do_printf, ...) do {                 \
    char __addr_ ## __LINE__[INET6_ADDRSTRLEN];                         \
    char __raddr_ ## __LINE__[INET6_ADDRSTRLEN];                        \
    uint16_t __port_ ## __LINE__, __rport_ ## __LINE__;                 \
    char __rport_str_ ## __LINE__[6];                                   \
    int __has_raddr_ ## __LINE__ =                                      \
      (cand)->ic_type != ICE_TYPE_HOST;                                 \
                                                                        \
    format_address(&(cand)->ic_addr.ksa, sizeof((cand)->ic_addr),       \
                   __addr_ ## __LINE__, sizeof(__addr_ ## __LINE__),    \
                   &__port_ ## __LINE__);                               \
    if ( __has_raddr_ ## __LINE__ ) {                                   \
      format_address(&(cand)->ic_raddr.ksa, sizeof((cand)->ic_raddr),   \
                     __raddr_ ## __LINE__, sizeof(__raddr_ ## __LINE__),\
                     &__rport_ ## __LINE__);                            \
      snprintf(__rport_str_ ## __LINE__,                                \
               sizeof(__rport_str_ ## __LINE__), "%5d",                 \
               __rport_ ## __LINE__);                                   \
    } else {                                                            \
      __raddr_ ## __LINE__[0] = '\0';                                   \
      __rport_str_ ## __LINE__[0] = '\0';                               \
    }                                                                   \
                                                                        \
    do_printf(__VA_ARGS__ "candidate:%.*s " /* Foundation */            \
              "%d %s %u " /* Component Type Priority */                 \
              "%s %d typ %s" /* Address Port Type */                    \
              "%s%s%s%s", /* raddr? <raddr> rport? <rport> */           \
              (int)sizeof((cand)->ic_foundation),                       \
              (cand)->ic_foundation,                                    \
              (cand)->ic_component,                                     \
              ice_transport_str((cand)->ic_transport),                  \
              (cand)->ic_priority,                                      \
              __addr_ ## __LINE__, __port_ ## __LINE__,                 \
              ice_type_str((cand)->ic_type),                            \
              __has_raddr_ ## __LINE__ ? " raddr " : "",                \
              __has_raddr_ ## __LINE__ ? __raddr_ ## __LINE__ : "",     \
              __has_raddr_ ## __LINE__ ? " rport " : "",                \
              __has_raddr_ ## __LINE__ ?                                \
                __rport_str_ ## __LINE__ : "");                         \
  } while (0)

static const char *ice_transport_str(int ts);
static const char *ice_type_str(int ty);
static uint32_t icecand_recommend_priority(struct icecand *ic, uint16_t local_pref);
static int icecand_parse(struct icecand *ic, const char *vls, const char *vle);

#define CANDSRC_SUBSCRIBE_READ(cs) do {                           \
    uint32_t __did_sub_ ## __LINE__;                              \
    PCONN_WREF((cs)->cs_pconn); /* For FD_SUB_READ */             \
    PCONN_WREF((cs)->cs_pconn); /* For FD_SUB_ERROR */            \
    __did_sub_ ## __LINE__ = eventloop_subscribe_fd               \
      (&(cs)->cs_pconn->pc_appstate->as_eventloop,                \
       (cs)->cs_socket,                                           \
       FD_SUB_READ | FD_SUB_ERROR, &(cs)->cs_socket_sub);         \
    if ( (__did_sub_ ## __LINE__ & FD_SUB_READ) == 0 )            \
      PCONN_WUNREF((cs)->cs_pconn);                               \
    if ( (__did_sub_ ## __LINE__ & FD_SUB_ERROR) == 0 )           \
      PCONN_WUNREF((cs)->cs_pconn);                               \
  } while(0);
#define CANDSRC_SUBSCRIBE_WRITE(cs) do {                \
    uint32_t __did_sub_ ## __LINE__;                    \
    PCONN_WREF((cs)->cs_pconn);                         \
    PCONN_WREF((cs)->cs_pconn);                         \
    __did_sub_ ## __LINE__ = eventloop_subscribe_fd     \
      (&(cs)->cs_pconn->pc_appstate->as_eventloop,      \
       (cs)->cs_socket, FD_SUB_WRITE | FD_SUB_ERROR,    \
       &(cs)->cs_socket_sub);                           \
    if ( (__did_sub_ ## __LINE__ & FD_SUB_WRITE) == 0 ) \
      PCONN_WUNREF((cs)->cs_pconn);                     \
    if ( (__did_sub_ ## __LINE__ & FD_SUB_ERROR) == 0 ) \
      PCONN_WUNREF((cs)->cs_pconn);                     \
  } while(0)

#define OP_PCONN_EXPIRES EVT_CTL_CUSTOM
#define OP_PCONN_STARTS (EVT_CTL_CUSTOM + 1)
#define OP_PCONN_SOCKET (EVT_CTL_CUSTOM + 2)
#define OP_PCONN_CANDSRC_RETRANSMIT (EVT_CTL_CUSTOM + 3)
#define OP_PCONN_CONN_CHECK_TIMER_RINGS (EVT_CTL_CUSTOM + 4)
#define OP_PCONN_CONN_CHECK_TIMEOUT (EVT_CTL_CUSTOM + 5)
#define OP_PCONN_NEW_TOKEN (EVT_CTL_CUSTOM + 6)

static void pconn_fn(struct eventloop *el, int op, void *arg);
static void pconn_free(struct pconn *pc);

static int pconn_container_fn(struct container *c, int op, void *argp, ssize_t argl);

// Call when the pc->pc_state may have changed
static void pconn_ice_gathering_state_may_change(struct pconn *pc);
static void pconn_reset_connectivity_check_timer(struct pconn *pc);
static void pconn_reset_connectivity_check_timeout(struct pconn *pc);

static void pconn_teardown_established(struct pconn *pc);

static void pconn_connectivity_check_succeeds(struct pconn *pc, int cand_pair_ix, int flags);

static void pconn_on_new_tokens(struct pconn *pc);
static void pconn_enable_traffic_deferred(struct pconn *pc);

#define PCONN_LOCAL_CANDIDATE  1
#define PCONN_REMOTE_CANDIDATE 2

// Add the given ice candidate to the pconn. Returns 1 if the
// candidate was added, 0 if the candidate already existed, and -1 on
// error.
//
// cand_type is PCONN_LOCAL_CANDIDATE or PCONN_REMOTE_CANDIDATE
//
// cand is copied
//
// pc_mutex must be held
static int pconn_add_ice_candidate(struct pconn *pc, int cand_type, struct icecand *cand);

static void pconn_on_established(struct pconn *pc);
static void pconn_on_sctp_packet(struct sctpentry *se, const void *buf, size_t sz);

// Find the candidate pair belonging to the given peer_addr on the given candsrc.
//
// Returns a valid icecandpair on success, or NULL on failure. If icp_ix is not NULL, it is filled
// in with thte index of the returned pair; otherwise, it is set to -1.
static struct icecandpair *pconn_find_candidate_pair(struct pconn *pc, struct candsrc *src,
                                                     struct sockaddr *peer_addr, size_t peer_addr_sz,
                                                     int *icp_ix);

// Returns 0 if the DTLS is right, -1 otherwise
static int pconn_ensure_dtls(struct pconn *pc);
static void pconn_dtls_handshake(struct pconn *pc);

static int pconn_sdp_new_media_fn(void *pc_);
static int pconn_sdp_media_ctl_fn(void *pc_, int, void *arg);
static int pconn_sdp_attr_fn(void *pc_, const char *nms, const char *nme,
                               const char *vls, const char *vle);
static int pconn_parse_remote_fingerprint(struct pconn *pc, const char *vls, const char *vle);

// Returns the index of candsrc cs in pc or -1 on error
static int pconn_cs_idx(struct pconn *pc, struct candsrc *cs);

static int candsrc_jitter() {
  int r;
  if ( !RAND_bytes((unsigned char *)&r, sizeof(r)) ) r = 100;

  return r % PCONN_CANDSRC_JITTER;
}

static void candsrc_release(struct candsrc *src) {
  SAFE_ASSERT( eventloop_cancel_timer(&src->cs_pconn->pc_appstate->as_eventloop, &src->cs_retransmit) == 0 );

  if ( src->cs_socket ) {
    fprintf(stderr, "Closing cs socket\n");
    close(src->cs_socket);
    src->cs_socket = 0;
  }
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
    // Note: always use sendto, as the connect()/bind() sequence in
    // candsrc_add_host_candidate may execute simultaneously.
    err = sendto(src->cs_socket, &msg, STUN_MSG_LENGTH(&msg), 0,
                 &src->cs_svr.ksa, sizeof(src->cs_svr));
    if ( err < 0 ) {
      if ( errno == EWOULDBLOCK ) {
        fprintf(stderr, "candsrc_transmit_binding: could not retransmit, because there's no space in the buffer\n");
      } else
        perror("candsrc_transmit_binding: sendto");
    }
  } else {
    fprintf(stderr, "candsrc_transmit_binding: TODO send STUNS requests\n");
  }
}

static int candsrc_process_binding_response(struct candsrc *cs, struct stunmsg *msg) {
  kite_sock_addr addr;
  socklen_t addr_sz = sizeof(addr);
  int err;

  if ( cs->cs_state == CS_STATE_BINDING ) {
    err = stun_process_binding_response(msg, &addr.ksa, &addr_sz);
    if ( err < 0 ) {
      fprintf(stderr, "candsrc_receive_response: invalid binding response\n");
    } else {
      struct icecand candidate;

      if ( eventloop_cancel_timer(&cs->cs_pconn->pc_appstate->as_eventloop, &cs->cs_retransmit) )
        PCONN_WUNREF(cs->cs_pconn);

      // Get raddr

      // Note, both these functions need to be called while pc_mutex
      // is held, but that occurs in the OP_PCONN_SOCKET handler.
      candidate.ic_component = 1;
      candidate.ic_transport = IPPROTO_UDP;
      candidate.ic_type = ICE_TYPE_SRFLX;

      assert(addr_sz <= sizeof(candidate.ic_addr));
      assert(cs->cs_local_addr.ksa.sa_family != AF_UNSPEC);
      memcpy(&candidate.ic_addr, &addr, addr_sz);
      memcpy(&candidate.ic_raddr, &cs->cs_local_addr, sizeof(candidate.ic_raddr));

      candidate.ic_candsrc_ix = pconn_cs_idx(cs->cs_pconn, cs);
      assert(candidate.ic_candsrc_ix >= 0);

      if ( pconn_add_ice_candidate(cs->cs_pconn, PCONN_LOCAL_CANDIDATE, &candidate) ) {
        fprintf(stderr, "This candidate was accepted, so we will keep this alive\n");
        // If we generate a server reflexive candidate, we have to keep
        // it alive, per the ICE spec
        cs->cs_state = CS_STATE_KEEPALIVE;

        pconn_ice_gathering_state_may_change(cs->cs_pconn);
        // TODO set a timer to resend a binding request
      }
    }
  }
  return 0;
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
      if ( pthread_mutex_lock(&src->cs_pconn->pc_mutex) == 0 ) {
        pconn_ice_gathering_state_may_change(src->cs_pconn);
        pthread_mutex_unlock(&src->cs_pconn->pc_mutex);
      }
    } else {
      if ( src->cs_flags & CS_FLAG_TURN )
        fprintf(stderr, "candsrc_retransmit: send TURN requests\n");
      else
        candsrc_transmit_binding(src);

      fprintf(stderr, "Sending binding request for candidate source %d\n", pconn_cs_idx(src->cs_pconn, src));

      timersub_set_from_now(&src->cs_retransmit,
                            candsrc_jitter() + (CS_RETRANSMIT_INTERVAL << src->cs_retries));
      PCONN_WREF(src->cs_pconn);
      eventloop_subscribe_timer(&src->cs_pconn->pc_appstate->as_eventloop, &src->cs_retransmit);
    }
    break;
  case CS_STATE_ERROR:
  case CS_STATE_DONE:
  default:
    break;
  }
}

static int pconn_stun_user_fn(const char *username, size_t username_sz,
                              const char **password_ptr, size_t *password_sz,
                              void *pc_) {
  struct pconn *pc = (struct pconn *) pc_;
  const char *local_ufrag_end, *remote_ufrag_start;

  if ( username_sz > 256 ) return STUN_UNAUTHORIZED; // TODO more robust

  if ( PCONN_READY_FOR_ICE(pc) ) {
    char username_null[username_sz + 1];
    memcpy(username_null, username, username_sz);
    username_null[username_sz] = '\0';

    local_ufrag_end = strchr(username_null, ':');
    remote_ufrag_start = local_ufrag_end + 1;

    if ( local_ufrag_end ) {
//      fprintf(stderr, "pconn_stun_user_fn: got local %.*s, remote %.*s\n",
//              (int)(local_ufrag_end - username_null), username_null,
//              (int)(username_sz + username_null - remote_ufrag_start), remote_ufrag_start);

      if ( strncmp(pc->pc_our_ufrag, username_null, local_ufrag_end - username_null) == 0 &&
           strncmp(pc->pc_remote_ufrag, remote_ufrag_start,
                   username_sz + username_null - remote_ufrag_start) == 0 ) {
        *password_ptr = pc->pc_our_pwd;
        *password_sz = sizeof(pc->pc_our_pwd);
        return STUN_SUCCESS;
      }
    }
  }

  return STUN_UNAUTHORIZED;
}

static int pconn_stun_attr_fn(uint16_t attr_name, const char *attr_data, size_t attr_sz,
                              void *pc_) {
  struct pconn *pc = (struct pconn *) pc_;
  int remote_role = 0, expected_local_role = 0;
  uint64_t remote_tie_breaker;

  switch ( attr_name ) {
  case STUN_ATTR_ICE_CONTROLLING:
  case STUN_ATTR_ICE_CONTROLLED:
    if ( attr_sz != sizeof(remote_tie_breaker) )
      return STUN_BAD_REQUEST;

    memcpy(&remote_tie_breaker, attr_data, sizeof(remote_tie_breaker));
    remote_tie_breaker = ntohll(remote_tie_breaker);

    if ( attr_name == STUN_ATTR_ICE_CONTROLLING )
      remote_role = ICE_ROLE_CONTROLLING;
    else
      remote_role = ICE_ROLE_CONTROLLED;

    if ( remote_role == ICE_ROLE_CONTROLLING )
      expected_local_role = ICE_ROLE_CONTROLLED;
    else
      expected_local_role = ICE_ROLE_CONTROLLING;

    if ( expected_local_role != pc->pc_ice_role ) {
      fprintf(stderr, "Role conflict. Remote is %d, we expected ourselves to be %d, but we are %d\n",
              remote_role, expected_local_role, pc->pc_ice_role);
      if ( pc->pc_ice_role == ICE_ROLE_CONTROLLING ) {
        // https://tools.ietf.org/html/rfc5245
        //
        // ICE RFC 7.2.1.1 --
        //
        // If the agent is in the controlling role, and the
        // ICE-CONTROLLING attribute is present in the request:
        //
        // If our tie-breaker is larger than or equal to the contents
        // of the attribute, generate a binding error response with
        // 487. Otherwise, switch to the controlled role
        if ( pc->pc_tie_breaker >= remote_tie_breaker )
          return STUN_ROLE_CONFLICT;
        else
          pc->pc_ice_role = ICE_ROLE_CONTROLLED;
      } else {
        // If the agent is in the controlled role, and the
        // ICE-CONTROLLED attribute is present in the request:
        //
        // If our tie-breaker is larger than or equal to the contents
        // of the attribute, switch to controlling role. Otherwise
        // generate role conflict
        if ( pc->pc_tie_breaker >= remote_tie_breaker )
          pc->pc_ice_role = ICE_ROLE_CONTROLLING;
        else
          return STUN_ROLE_CONFLICT;
      }
    }

    // This is expected
    return STUN_SUCCESS;
  default:
    return STUN_SUCCESS;
  }
}

static void candsrc_send_binding_response(struct candsrc *cs, const struct stunmsg *msg,
                                          struct sockaddr *peer_addr, size_t peer_addr_sz) {
  struct stunmsg rsp;
  struct stunattr *attr;

  int err;

  const char *pwd = cs->cs_pconn->pc_our_pwd;
  size_t pwd_sz = PCONN_OUR_PASSWORD_SIZE;

  STUN_INIT_MSG(&rsp, STUN_BINDING | STUN_RESPONSE);
  memcpy(&rsp.sm_tx_id, &msg->sm_tx_id, sizeof(rsp.sm_tx_id));
  attr = STUN_FIRSTATTR(&rsp);

  // Intentionally overwrite username attribute
  //  attr = STUN_NEXTATTR(attr);
  err = stun_add_xor_mapped_address_attr(&attr, &rsp, sizeof(rsp), peer_addr, peer_addr_sz);
  if ( err < 0 ) {
    fprintf(stderr, "candsrc_send_binding_response: could not add mapped address attributes\n");
    return;
  }

  attr = STUN_NEXTATTR(attr);
  err = stun_add_message_integrity(&attr, &rsp, sizeof(rsp), pwd, pwd_sz);
  if ( err < 0 ) {
    fprintf(stderr, "candsrc_send_binding_response: could not add message integrity\n");
    return;
  }

  STUN_FINISH_WITH_FINGERPRINT(attr, &rsp, sizeof(rsp), err);
  if ( err < 0 ) {
    fprintf(stderr, "candsrc_send_binding_response: could not add fingerprint\n");
    return;
  }

  err = sendto(cs->cs_socket, &rsp, STUN_MSG_LENGTH(&rsp), 0,
               peer_addr, peer_addr_sz);
  if ( err < 0 )
    perror("candsrc_send_binding_response: sendto");
  else {
    if ( !pconn_find_candidate_pair(cs->cs_pconn, cs, peer_addr, peer_addr_sz, NULL) ) {
      struct icecand candidate;
      // Add peer reflexive remote candidate
      candidate.ic_component = 1;
      candidate.ic_transport = IPPROTO_UDP;
      candidate.ic_type = ICE_TYPE_PRFLX;
      memcpy(&candidate.ic_addr, peer_addr, peer_addr_sz);
      memcpy(&candidate.ic_raddr, peer_addr, peer_addr_sz);

      random_printable_string(candidate.ic_foundation, ICE_FOUNDATION_LEN);
      candidate.ic_foundation[ICE_FOUNDATION_LEN] = '\0';

      pconn_add_ice_candidate(cs->cs_pconn, PCONN_REMOTE_CANDIDATE, &candidate);
    }
  }
//  else {
//    struct pconn *pc = cs->cs_pconn;
//    int icp_ix = -1;
//
//    if ( pconn_find_candidate_pair(cs->cs_pconn, cs, peer_addr, peer_addr_sz, &icp_ix) ) {
//      pconn_connectivity_check_succeeds(pc, icp_ix, ICECANDPAIR_FLAG_RECEIVED);
//    } else {
//      fprintf(stderr, "Could not match this binding request with any candidate pair\n");
//
//      // TODO add peer reflexive candidate?
//    }
//  }
}

static void candsrc_send_error_response(struct candsrc *cs, const struct stunmsg *msg,
                                        int err_code, struct stunvalidation *sv,
                                        struct sockaddr *peer_addr, size_t peer_addr_sz) {
  struct stunmsg rsp;
  int err;

  err = stun_format_error(&rsp, sizeof(rsp), msg, err_code, sv);
  if ( err < 0 ) {
    fprintf(stderr, "stun_format_response: failed\n");
  } else {
    // Send response back, if there's no space do nothing
    err = sendto(cs->cs_socket, &rsp, STUN_MSG_LENGTH(&rsp), 0,
                 peer_addr, peer_addr_sz);
    if ( err < 0 )
      perror("candsrc_handle_response: sendto");
  }
}

// pconn mutex is locked, so we can use the incoming_pkt buffer
static int candsrc_handle_response(struct candsrc *cs) {
  int err, pkt_sz, i;
  kite_sock_addr peer_addr;
  socklen_t peer_addr_sz = sizeof(peer_addr);

  pkt_sz = err = recvfrom(cs->cs_socket, cs->cs_pconn->pc_incoming_pkt,
                          sizeof(cs->cs_pconn->pc_incoming_pkt), 0,
                          &peer_addr.ksa, &peer_addr_sz);
  if ( err < 0 ) {
    if ( errno == EWOULDBLOCK || errno == EAGAIN )
      return 0;
    else {
      perror("candsrc_handle_response: recv");
      return -1;
    }
  }

  // Check if this is DTLS media
  if ( pkt_sz > 0 && IS_DTLS_PACKET(cs->cs_pconn->pc_incoming_pkt[0]) ) {
    if ( pconn_ensure_dtls(cs->cs_pconn) < 0 ) {
      fprintf(stderr, "Ignoring DTLS packet, because we could not create DTLS context\n");
    } else {
      BIO_reset(SSL_get_rbio(cs->cs_pconn->pc_dtls));
      BIO_STATIC_SET_READ_SZ(&cs->cs_pconn->pc_static_pkt_bio, pkt_sz);
      //fprintf(stderr, "Accepting DTLS packet of size %d\n", pkt_sz);
      if ( cs->cs_pconn->pc_state == PCONN_STATE_ESTABLISHED ) {
	unsigned char my_buf[sizeof(cs->cs_pconn->pc_incoming_pkt)];
	pkt_sz = SSL_read(cs->cs_pconn->pc_dtls, my_buf, sizeof(my_buf));
	if ( pkt_sz <= 0 ) {
	  fprintf(stderr, "error while trying to read packet: %d\n", pkt_sz);
	} else {
	  //              fprintf(stderr, "Got DTLS packet while established of size: %d\n", pkt_sz);
	  //              print_hex_dump_fp(stderr, (const unsigned char *) my_buf, pkt_sz);
	  
	  // Only write the packet if the webrtc-proxy is up
	  //fprintf(stderr, "Writing packett to bridge of size %u (webrtc proxy %d)\n", pkt_sz, cs->cs_pconn->pc_webrtc_proxy);
	  bridge_write_from_foreign_pkt(&cs->cs_pconn->pc_appstate->as_bridge,
					&cs->cs_pconn->pc_container,
					&peer_addr.ksa, peer_addr_sz,
					my_buf, pkt_sz);
	}
      } else {
	pconn_dtls_handshake(cs->cs_pconn);
      }
    }
  } else {
    struct stunvalidation sv;

    sv.sv_flags = STUN_VALIDATE_RESPONSE;
    sv.sv_req_code = STUN_BINDING;
    sv.sv_tx_id = NULL;
    sv.sv_user_cb = pconn_stun_user_fn;
    sv.sv_unknown_cb = pconn_stun_attr_fn;
    sv.sv_user_data = cs->cs_pconn;
    sv.sv_unknown_attrs = NULL;
    sv.sv_unknown_attrs_sz = 0;

    err = stun_validate(cs->cs_pconn->pc_incoming_pkt, pkt_sz, &sv);
    if ( err == STUN_SUCCESS ) {
      struct stunmsg *msg = (struct stunmsg *)cs->cs_pconn->pc_incoming_pkt;

      // If this is STUN, attempt to match up
      if ( memcmp(&cs->cs_tx_id, &msg->sm_tx_id, sizeof(msg->sm_tx_id)) == 0 ) {
        candsrc_process_binding_response(cs, msg);
      } else {
        // This could be a connectivity check. Check to see if the transaction ID matches any candidate pair
        for ( i = 0; i < cs->cs_pconn->pc_candidate_pairs_count; ++i ) {
//	  fprintf(stderr, "Check binding response(cand %d): Got txid %08x%08x%08x. Cand txid is %08x%08x%08x\n",
//		  i, msg->sm_tx_id.a, msg->sm_tx_id.b, msg->sm_tx_id.c,
//		  cs->cs_pconn->pc_candidate_pairs_sorted[i]->icp_tx_id.a,
//		  
//		  cs->cs_pconn->pc_candidate_pairs_sorted[i]->icp_tx_id.b,
//		  cs->cs_pconn->pc_candidate_pairs_sorted[i]->icp_tx_id.c);
          if ( memcmp(&cs->cs_pconn->pc_candidate_pairs_sorted[i]->icp_tx_id,
                      &msg->sm_tx_id, sizeof(msg->sm_tx_id)) == 0 ) {
            pconn_connectivity_check_succeeds(cs->cs_pconn, i, ICECANDPAIR_FLAG_NOMINATED);
            break;
          }
        }

        return 0;
      }
    } else {
      if ( PCONN_READY_FOR_ICE(cs->cs_pconn) ) {
        uint16_t unknown_attrs[16];

        sv.sv_flags = STUN_VALIDATE_REQUEST | STUN_NEED_FINGERPRINT | STUN_NEED_MESSAGE_INTEGRITY;
        sv.sv_unknown_attrs = unknown_attrs;
        sv.sv_unknown_attrs_sz = sizeof(unknown_attrs) / sizeof(unknown_attrs[0]);
        err = stun_validate(cs->cs_pconn->pc_incoming_pkt, pkt_sz, &sv);
        if ( err == STUN_SUCCESS ) {
          struct stunmsg *msg = (struct stunmsg *)cs->cs_pconn->pc_incoming_pkt;

          //fprintf(stderr, "Received binding request\n");
          if ( STUN_REQUEST_TYPE(msg) == STUN_BINDING ) {
            candsrc_send_binding_response(cs, msg, &peer_addr.ksa, peer_addr_sz);
          } else
            fprintf(stderr, "STUN message of unknown type %04x\n", STUN_REQUEST_TYPE(msg));
        } else if ( err > 0 ) { // Error to send back
          candsrc_send_error_response(cs, (struct stunmsg *) cs->cs_pconn->pc_incoming_pkt,
                                      err, &sv, &peer_addr.ksa, peer_addr_sz);
        } else {
          fprintf(stderr, "error: stun_validate returned %d: %s\n", err, stun_strerror(err));
        }
      } else
        fprintf(stderr, "candsrc_handle_response: ignoring packet because ICE has not completed\n");
    }
  }

  return 0;
}

static void candsrc_send_outgoing(struct candsrc *cs) {
  struct pconn *pc = cs->cs_pconn;
  char outgoing[PCONN_MAX_PACKET_SIZE];

  while ( pc->pc_outgoing_size > 4 ) {
    int err;
    uint32_t sz;
    size_t next_offs;
    size_t read_head = pc->pc_outgoing_offs;
    char *out = pc->pc_outgoing_pkt + pc->pc_outgoing_offs;

    memcpy(&sz, out, 4);

    if ( (sz + 4) > pc->pc_outgoing_size ) {
      fprintf(stderr, "candsrc_send_outgoing: invalid state %u %zu\n", sz + 4, pc->pc_outgoing_size);
      break;
    }

    assert( sz <= PCONN_MAX_PACKET_SIZE );

    read_head += 4;
    read_head %= sizeof(pc->pc_outgoing_pkt);

    if ( (sizeof(pc->pc_outgoing_pkt) - read_head) < sz ) {
      memcpy(outgoing, pc->pc_outgoing_pkt + read_head,
             sizeof(pc->pc_outgoing_pkt) - read_head);
      memcpy(outgoing + sizeof(pc->pc_outgoing_pkt) - read_head,
             pc->pc_outgoing_pkt,
             sz - (sizeof(pc->pc_outgoing_pkt) - read_head));
      next_offs = sz - (sizeof(pc->pc_outgoing_pkt) - read_head);
    } else {
      memcpy(outgoing, pc->pc_outgoing_pkt + read_head, sz);
      next_offs = read_head + sz;
    }

    next_offs %= sizeof(pc->pc_outgoing_pkt);
    next_offs = ((next_offs + 3) / 4) * 4;
    next_offs %= sizeof(pc->pc_outgoing_pkt);

    BIO_reset(SSL_get_rbio(cs->cs_pconn->pc_dtls));
    BIO_STATIC_SET_READ_SZ(&cs->cs_pconn->pc_static_pkt_bio, 0);
//    fprintf(stderr, "candsrc_send_outgoing: send packet of size %u (cs idx %d)\nfrom address",
//            pconn_cs_idx(cs->cs_pconn, cs), sz);
//    dump_address(stderr, &cs->cs_local_addr.ksa, sizeof(cs->cs_local_addr));
//    fprintf(stderr, "\n");
    err = SSL_write(cs->cs_pconn->pc_dtls, outgoing, sz);
    if ( err <= 0 ) {
      if ( err == 0 ) {
        fprintf(stderr, "candsrc_send_outgoing: could not write anything\n");
        break;
      } else {
        err = SSL_get_error(cs->cs_pconn->pc_dtls, err);
        if ( err == SSL_ERROR_WANT_WRITE ) {
          fprintf(stderr, "candsrc_send_outgoing: needs write\n");
          break;
        } else {
          fprintf(stderr, "candsrc_send_outgoing: unknown ssl error %d\n", err);
          ERR_print_errors_fp(stderr);
          break;
        }
      }
    } else {
      //      fprintf(stderr, "candsrc_send_outgoing: sent packet of size %u. Next offset is %lu\n", sz, next_offs);
      pc->pc_outgoing_offs = next_offs;
      pc->pc_outgoing_size -= 4 + sz;
    }
  }

  if ( pc->pc_outgoing_size < 4 ) pc->pc_outgoing_size = 0;
  return;
}

static void candsrc_send_connectivity_check(struct candsrc *cs) {
  struct icecandpair *pair = cs->cs_scheduled_connectivity_check;
  struct icecand *remote;
  struct stunmsg msg;
  struct stunattr *attr;
  int remote_ufrag_len, err;

  struct icecand fake_peer;
  uint32_t peer_priority;
  uint64_t tie_breaker_network = htonll(cs->cs_pconn->pc_tie_breaker);

  cs->cs_scheduled_connectivity_check = NULL;

  if ( !PCONN_READY_FOR_ICE(cs->cs_pconn) ) {
    fprintf(stderr, "candsrc_send_connectivity_check: failed because we're not ready for ice\n");
    return;
  }

  if ( !pair || pair->icp_remote_ix >= cs->cs_pconn->pc_remote_ice_candidates_count ) {
    fprintf(stderr, "candsrc_send_connectivity_check: invalid pair or remote ix out of range\n");
    return;
  }

  remote = &cs->cs_pconn->pc_remote_ice_candidates[pair->icp_remote_ix];
  if ( !remote ) {
    fprintf(stderr, "candsrc_send_connectivity_check: NULL in pc_remote_ice_candidates\n");
    return;
  }

  fake_peer.ic_component = remote->ic_component;
  fake_peer.ic_transport = remote->ic_transport;
  fake_peer.ic_type = ICE_TYPE_PRFLX;
  peer_priority = htonl(icecand_recommend_priority(&fake_peer, 0));

  // The connectivity check should have the USERNAME, PRIORITY, MESSAGE-INTEGRITY, and FINGERPRINT
  // attributes. If we're in the controlling role, then we should send USE-CANDIDATE and
  // ICE-CONTROLLING attributes as well. Otherwise, send ICE-CONTROLLED

  STUN_INIT_MSG(&msg, STUN_BINDING);
  memcpy(&msg.sm_tx_id, &pair->icp_tx_id, sizeof(msg.sm_tx_id));

  attr = STUN_FIRSTATTR(&msg);
  remote_ufrag_len = strlen(cs->cs_pconn->pc_remote_ufrag);
  assert( STUN_CAN_WRITE_ATTR(attr, &msg, sizeof(msg)) );
  STUN_INIT_ATTR(attr, STUN_ATTR_USERNAME, PCONN_OUR_UFRAG_SIZE + 1 + remote_ufrag_len);
  assert( STUN_ATTR_IS_VALID(attr, &msg, sizeof(msg)) );
  memcpy(STUN_ATTR_DATA(attr), cs->cs_pconn->pc_remote_ufrag, remote_ufrag_len);
  memcpy(STUN_ATTR_DATA(attr) + remote_ufrag_len, ":", 1);
  memcpy(STUN_ATTR_DATA(attr) + remote_ufrag_len + 1, cs->cs_pconn->pc_our_ufrag, PCONN_OUR_UFRAG_SIZE);

  attr = STUN_NEXTATTR(attr);
  assert( STUN_CAN_WRITE_ATTR(attr, &msg, sizeof(msg)) );
  STUN_INIT_ATTR(attr, STUN_ATTR_PRIORITY, sizeof(peer_priority));
  assert( STUN_ATTR_IS_VALID(attr, &msg, sizeof(msg)) );
  memcpy(STUN_ATTR_DATA(attr), &peer_priority, sizeof(peer_priority));

  attr = STUN_NEXTATTR(attr);
  assert( STUN_CAN_WRITE_ATTR(attr, &msg, sizeof(msg)) );
  STUN_INIT_ATTR(attr,
                 (cs->cs_pconn->pc_ice_role == ICE_ROLE_CONTROLLING ?
                  STUN_ATTR_ICE_CONTROLLING :
                  STUN_ATTR_ICE_CONTROLLED),
                 sizeof(tie_breaker_network));
  assert( STUN_ATTR_IS_VALID(attr, &msg, sizeof(msg)) );
  memcpy(STUN_ATTR_DATA(attr), &tie_breaker_network, sizeof(tie_breaker_network));

  if ( cs->cs_pconn->pc_ice_role == ICE_ROLE_CONTROLLING ) {
    attr = STUN_NEXTATTR(attr);
    assert( STUN_CAN_WRITE_ATTR(attr, &msg, sizeof(msg)) );
    STUN_INIT_ATTR(attr, STUN_ATTR_USE_CANDIDATE, 0);
  }

  attr = STUN_NEXTATTR(attr);
  err = stun_add_message_integrity(&attr, &msg, sizeof(msg), cs->cs_pconn->pc_remote_pwd, strlen(cs->cs_pconn->pc_remote_pwd));
  if ( err < 0 ) {
    fprintf(stderr, "Could not add message integrity to connectivity check\n");
    return;
  }

  STUN_FINISH_WITH_FINGERPRINT(attr, &msg, sizeof(msg), err);
  if ( err < 0 ) {
    fprintf(stderr, "Could not add fingerprint to connectivity check\n");
    return;
  }

  err = sendto(cs->cs_socket, &msg, STUN_MSG_LENGTH(&msg), 0,
               &remote->ic_addr.ksa, sizeof(remote->ic_addr));
  if ( err < 0 ) {
    err = errno;
    if ( errno == EWOULDBLOCK ) {
      fprintf(stderr, "candsrc_send_connectivity_check: would block\n");
    } else {
      perror("candsrc_send_connectivity_check: sendto");
    }
  }
}

// Adds the given cand src's host candidate to the pconn. pconn_mutex
// must be held.
//
// At this point, the socket is connect()ed, but it needs to be
// bind()ed in order to make it accept packets from any remote address.
//
// According to http://man7.org/linux/man-pages/man2/connect.2.html
// connecting to AF_UNSPEC disconnects the socket.x
static void candsrc_add_host_candidate(struct candsrc *cs) {
  socklen_t addrsz = sizeof(cs->cs_local_addr);
  struct icecand candidate;
  struct sockaddr disconnect_addr;
  int err, cs_idx;

  cs_idx = pconn_cs_idx(cs->cs_pconn, cs);
  if ( cs_idx < 0 ) {
    fprintf(stderr, "candsrc_add_host_candidate: invalid candidate source\n");
    return;
  }

  err = getsockname(cs->cs_socket, &cs->cs_local_addr.ksa, &addrsz);
  if ( err < 0 ) {
    perror("candsrc_add_host_candidate: getsockname");
    return;
  }

  candidate.ic_component = 1;
  candidate.ic_transport = IPPROTO_UDP;
  candidate.ic_type = ICE_TYPE_HOST;
  memcpy(&candidate.ic_addr, &cs->cs_local_addr, addrsz);
  candidate.ic_candsrc_ix = cs_idx;

  pconn_add_ice_candidate(cs->cs_pconn, PCONN_LOCAL_CANDIDATE, &candidate);

  // Now disconnect and rebind the socket
  disconnect_addr.sa_family = AF_UNSPEC;
  err = connect(cs->cs_socket, &disconnect_addr, sizeof(disconnect_addr));
  if ( err < 0 ) {
    perror("candsrc_add_host_candidate: connect (disconnect)");
  }

  fprintf(stderr, "Binding to ");
  dump_address(stderr, &cs->cs_local_addr.ksa, addrsz);
  fprintf(stderr, "\n");
  err = bind(cs->cs_socket, &cs->cs_local_addr.ksa, addrsz);
  if ( err < 0 ) {
    perror("candsrc_add_host_candidate: bind");
  }

}

int icecand_equivalent(struct icecand *a, struct icecand *b) {
  if ( a->ic_type == b->ic_type && a->ic_transport == b->ic_transport ) {
    // STUN servers should be the same if it's not reflexive or relayed
    if ( a->ic_type != ICE_TYPE_HOST && a->ic_candsrc_ix != b->ic_candsrc_ix )
      return 0;

    // IP addresses should be the same
    if ( a->ic_addr.ksa.sa_family != b->ic_addr.ksa.sa_family ) return 0;

    if ( a->ic_addr.ksa.sa_family == AF_INET ) {
      return a->ic_addr.ksa_ipv4.sin_addr.s_addr == b->ic_addr.ksa_ipv4.sin_addr.s_addr &&
        a->ic_addr.ksa_ipv4.sin_port == b->ic_addr.ksa_ipv4.sin_port;
    } else if ( a->ic_addr.ksa.sa_family == AF_INET6 ) {
      return memcmp(a->ic_addr.ksa_ipv6.sin6_addr.s6_addr,
                    b->ic_addr.ksa_ipv6.sin6_addr.s6_addr, 16) == 0 &&
        a->ic_addr.ksa_ipv6.sin6_port == b->ic_addr.ksa_ipv6.sin6_port;
    } else return 0;
  } else
    return 0;
}

uint64_t icecand_pair_priority(struct pconn *pc, struct icecand *local, struct icecand *remote) {
  uint64_t g, d;
  if ( pc->pc_ice_role == ICE_ROLE_CONTROLLING ) {
    g = local->ic_priority;
    d = remote->ic_priority;
  } else {
    g = remote->ic_priority;
    d = local->ic_priority;
  }

  return ((g < d ? g : d) << 32) + 2 * (g > d ? g : d) + (g > d ? 1 : 0);
}

static void pconn_delayed_start(struct pconn *pc) {
  struct appstate *app = pc->pc_appstate;
  struct flock *cur_flock, *tmp_flock;
  int err;

  fprintf(stderr, "pconn_delayed_start: start\n");
  pc->pc_ice_gathering_state = PCONN_ICE_GATHERING_STATE_GATHERING;
  // Collect all flocks and personas
  SAFE_RWLOCK_RDLOCK(&app->as_flocks_mutex);
  // For each flock, make a new candsrc
  pc->pc_candidate_sources = malloc(sizeof(pc->pc_candidate_sources[0]) *
                                    HASH_CNT(f_hh, app->as_flocks));
  if ( pc->pc_candidate_sources ) {
    HASH_ITER(f_hh, app->as_flocks, cur_flock, tmp_flock) {
      struct candsrc *cursrc = &pc->pc_candidate_sources[pc->pc_candidate_sources_count];
      if (cur_flock->f_flags & FLOCK_FLAG_KITE_ONLY) continue;

      pc->pc_candidate_sources_count++;

      if ( pthread_mutex_lock(&cur_flock->f_mutex) == 0 ) {
        memcpy(&cursrc->cs_svr, &cur_flock->f_cur_addr, sizeof(cur_flock->f_cur_addr));
        cursrc->cs_pconn = pc;
        cursrc->cs_flags = 0;
        cursrc->cs_retries = 0;
        cursrc->cs_host_candidate_added = 0;
        cursrc->cs_state = CS_STATE_INITIAL;
        cursrc->cs_scheduled_connectivity_check = NULL;

        if ( cur_flock->f_flags & FLOCK_FLAG_STUN_ONLY )
          cursrc->cs_flags |= CS_FLAG_STUN_ONLY;
        if ( cur_flock->f_flags & FLOCK_FLAG_INSECURE )
          cursrc->cs_flags |= CS_FLAG_INSECURE;

        if ( cursrc->cs_flags & CS_FLAG_INSECURE )
          cursrc->cs_state = CS_STATE_BINDING;
        else
          cursrc->cs_state = CS_STATE_ERROR; // TODO

        stun_random_tx_id(&cursrc->cs_tx_id);

        pthread_mutex_unlock(&cur_flock->f_mutex);
      } else {
        // TODO stop pconn
        fprintf(stderr, "pconn_delayed_start: couldn't lock flock mutex\n");
        pc->pc_candidate_sources_count --;
        continue;
      }

      // Open socket
      cursrc->cs_socket = socket(cursrc->cs_svr.ksa.sa_family, SOCK_DGRAM, 0);
      if ( cursrc->cs_socket < 0 ) {
        fprintf(stderr, "pconn_delayed_start: could not create socket\n");
        pc->pc_candidate_sources_count--;
        continue;
      } else {

        if ( set_socket_nonblocking(cursrc->cs_socket) < 0 ) {
          perror("pconn_delayed_start: set_socket_nonblocking");
        }

        // Attempt to connect to the given endpoint
        err = connect(cursrc->cs_socket, &cursrc->cs_svr.ksa, sizeof(cursrc->cs_svr));
        if ( err < 0 ) {
          if ( errno != EWOULDBLOCK )  // TODO EWOULDblock here
            perror("pconn_delayed_start: connect");
          else {
            cursrc->cs_local_addr.ksa.sa_family = AF_UNSPEC;
            CANDSRC_SUBSCRIBE_WRITE(cursrc);
          }
        } else {
          candsrc_add_host_candidate(cursrc);
        }

        fdsub_init(&cursrc->cs_socket_sub, &app->as_eventloop,
                   cursrc->cs_socket, OP_PCONN_SOCKET, pconn_fn);

        CANDSRC_SUBSCRIBE_READ(cursrc);

        // The source should start transmitting at some point
        PCONN_WREF(pc);
        timersub_init_from_now(&cursrc->cs_retransmit, candsrc_jitter(),
                                 OP_PCONN_CANDSRC_RETRANSMIT, pconn_fn);
        eventloop_subscribe_timer(&app->as_eventloop, &cursrc->cs_retransmit);
      }
    }
  } else
    fprintf(stderr, "pconn_delayed_start: out of memory to store flocks\n");
  pthread_rwlock_unlock(&app->as_flocks_mutex);

  fprintf(stderr, "pconn_delayed_start: finished\n");
}

static void pconn_fn(struct eventloop *el, int op, void *arg) {
  struct qdevent *evt = (struct qdevent *) arg;
  struct fdevent *fde = (struct fdevent *) arg;
  struct pconn *pc;
  struct candsrc *cs;
  int has_error = 0, cs_idx;

  switch ( op ) {
  case OP_PCONN_NEW_TOKEN:
    pc = STRUCT_FROM_BASE(struct pconn, pc_new_token_evt, evt->qde_sub);
    if ( PCONN_LOCK(pc) == 0 ) {
      if ( pthread_mutex_lock(&pc->pc_mutex) == 0 ) {
        pconn_on_new_tokens(pc);
        pthread_mutex_unlock(&pc->pc_mutex);
      }
      PCONN_UNREF(pc);
    }
    break;
  case OP_PCONN_EXPIRES:
    pc = STRUCT_FROM_BASE(struct pconn, pc_timeout, evt->qde_sub);
    pconn_finish(pc);
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
      fprintf(stderr, "Scheduling retransmission\n");
      candsrc_retransmit(cs);
      PCONN_UNREF(pc);
    }
    break;
  case OP_PCONN_CONN_CHECK_TIMEOUT:
    pc = STRUCT_FROM_BASE(struct pconn, pc_conn_check_timeout_timer, evt->qde_sub);
    if ( PCONN_LOCK(pc) == 0 ) {
      SAFE_MUTEX_LOCK(&pc->pc_mutex);
      pconn_teardown_established(pc);
      pthread_mutex_unlock(&pc->pc_mutex);
      PCONN_UNREF(pc);
    }

    break;
  case OP_PCONN_CONN_CHECK_TIMER_RINGS:
    pc = STRUCT_FROM_BASE(struct pconn, pc_conn_check_timer, evt->qde_sub);
    if ( PCONN_LOCK(pc) == 0 ) {
      struct icecandpair *p;
      struct icecand *local, *remote;

      SAFE_MUTEX_LOCK(&pc->pc_mutex);
      if ( pc->pc_active_candidate_pair < 0 ) {
        p = pc->pc_candidate_pairs_sorted[pc->pc_candidate_pair_pending_ix];
      } else
        p = pc->pc_candidate_pairs_sorted[pc->pc_active_candidate_pair];

      if ( p->icp_local_ix >= pc->pc_local_ice_candidates_count ||
           p->icp_remote_ix >= pc->pc_remote_ice_candidates_count ) {
        fprintf(stderr, "Candidate pair indices out of range\n");
        pconn_reset_connectivity_check_timer(pc);
      } else {
        local = &pc->pc_local_ice_candidates[p->icp_local_ix];
        remote = &pc->pc_remote_ice_candidates[p->icp_remote_ix];

        (void) remote; // Ignore unused for now

//	fprintf(stderr, "Schedule connectivity check on %d (active is %d)\n",
//		pc->pc_active_candidate_pair < 0 ? pc->pc_candidate_pair_pending_ix : pc->pc_active_candidate_pair,
//		pc->pc_active_candidate_pair);

        if ( pc->pc_active_candidate_pair < 0 ) {
          pc->pc_candidate_pair_pending_ix ++;
          pc->pc_candidate_pair_pending_ix %= pc->pc_candidate_pairs_count;
        }

        // When the candidate source does the write, it will re-enable the timer
        if ( local->ic_candsrc_ix < pc->pc_candidate_sources_count ) {
          pc->pc_candidate_sources[local->ic_candsrc_ix].
            cs_scheduled_connectivity_check = p;
          CANDSRC_SUBSCRIBE_WRITE(&pc->pc_candidate_sources[local->ic_candsrc_ix]);
        } else {
          fprintf(stderr, "Warning: invalid candidate source index in pair\n");
          pconn_reset_connectivity_check_timer(pc);
        }
      }

      pthread_mutex_unlock(&pc->pc_mutex);
      PCONN_UNREF(pc);
    }

    break;
  case OP_PCONN_SOCKET:
    cs = STRUCT_FROM_BASE(struct candsrc, cs_socket_sub, fde->fde_sub);
    pc = cs->cs_pconn;

    if ( FD_WRITE_AVAILABLE(fde) && PCONN_LOCK(pc) == 0 ) {
      struct icecandpair *icp;
      struct icecand *local_cand;
      // A write is available because we connect()ed. We can now add the host candidate
      SAFE_MUTEX_LOCK(&pc->pc_mutex);
      if ( !cs->cs_host_candidate_added ) {
        fprintf(stderr, "candsrc_add_host_candidate from write availability\n");
        candsrc_add_host_candidate(cs);
        cs->cs_host_candidate_added = 1;
      }

      //fprintf(stderr, "Got candsrc write %d %d\n", pconn_cs_idx(pc, cs), pc->pc_state);
      if ( pc->pc_active_candidate_pair >= 0 &&
           pc->pc_active_candidate_pair < pc->pc_candidate_pairs_count ) {
        icp = pc->pc_candidate_pairs_sorted[pc->pc_active_candidate_pair];
      } else
        icp = NULL;

      if ( icp && icp->icp_local_ix >= 0 &&
           icp->icp_local_ix < pc->pc_local_ice_candidates_count ) {
        local_cand = &pc->pc_local_ice_candidates[icp->icp_local_ix];
      } else
        local_cand = NULL;

      // If we're listening or accepting for DTLS or established, this may just be a DTLS
      // request
      if ( pc->pc_state == PCONN_STATE_DTLS_ACCEPTING ||
           pc->pc_state == PCONN_STATE_DTLS_CONNECTING ) {
        //fprintf(stderr, "do handshake\n");
        if ( pc->pc_dtls_needs_write )
          pconn_dtls_handshake(pc);
      } else if ( local_cand &&
                  pc->pc_state == PCONN_STATE_ESTABLISHED &&
                  pconn_cs_idx(pc, cs) == local_cand->ic_candsrc_ix &&
                  pc->pc_outgoing_size > 0 ) {
        //        fprintf(stderr, "candsrc_send_outgoing being called\n");
        candsrc_send_outgoing(cs);
      }

      if ( cs->cs_scheduled_connectivity_check ) {
        // Otherwise, this is a connectivity check
        pconn_reset_connectivity_check_timer(pc);
        candsrc_send_connectivity_check(cs);
      }
      pthread_mutex_unlock(&pc->pc_mutex);
      PCONN_UNREF(pc);
    }

    if ( FD_READ_PENDING(fde) && PCONN_LOCK(pc) == 0 ) {
      SAFE_MUTEX_LOCK(&pc->pc_mutex);
      cs_idx = pconn_cs_idx(pc, cs);
      if ( cs_idx >= 0 ) {
        if ( candsrc_handle_response(cs) < 0 )
          has_error = 1;
      }
      pthread_mutex_unlock(&pc->pc_mutex);
      PCONN_UNREF(pc);
    }

    if ( FD_ERROR_PENDING(fde) && PCONN_LOCK(pc) == 0 ) {
      has_error = 1;
      fprintf(stderr, "pconn_fn: TODO socket error cancel pconn\n");
      PCONN_UNREF(pc);
    }

    if ( !has_error ) {
      CANDSRC_SUBSCRIBE_READ(cs);
    }
    break;
  default:
    fprintf(stderr, "pconn_fn: Unknown op %d\n", op);
  }
}

static void pconn_free_fn(const struct shared *s, int level) {
  struct pconn *pc = STRUCT_FROM_BASE(struct pconn, pc_shared, s);

  fprintf(stderr, "free pconn at level %d\n", level);
  if ( level == SHFREE_NO_MORE_REFS ) {
    fprintf(stderr, "freeing pconn\n");

    pconn_free(pc);
  }
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
  ret->pc_sctp_port = DEFAULT_SCTP_PORT;
  ret->pc_dtls = NULL;
  ret->pc_dtls_needs_write = ret->pc_dtls_needs_read = 0;
  ret->pc_is_logged_in = 0;

  // Generate user fragment and password
  if ( !random_printable_string(ret->pc_our_ufrag, sizeof(ret->pc_our_ufrag)) ||
       !random_printable_string(ret->pc_our_pwd, sizeof(ret->pc_our_pwd)) ) {
    fprintf(stderr, "pconn_alloc: could not generate ICE parameters\n");
    pthread_mutex_destroy(&ret->pc_mutex);
    free(ret);
    return NULL;
  }

  if ( container_init(&ret->pc_container, &as->as_bridge, pconn_container_fn,
                      CONTAINER_FLAG_KILL_IMMEDIATELY | CONTAINER_FLAG_NETWORK_ONLY |
                      CONTAINER_FLAG_ENABLE_SCTP ) < 0 ) {
    fprintf(stderr, "pconn_alloc: could not allocate container\n");
    pthread_mutex_destroy(&ret->pc_mutex);
    free(ret);
    return NULL;
  }

  ret->pc_appstate = as;
  ret->pc_flock = f;
  ret->pc_conn_id = conn_id;
  ret->pc_candidate_sources = NULL;
  ret->pc_candidate_sources_count = 0;
  ret->pc_local_ice_candidates = NULL;
  ret->pc_local_ice_candidates_count = 0;
  ret->pc_local_ice_candidates_array_size = 0;
  ret->pc_remote_ice_candidates = NULL;
  ret->pc_remote_ice_candidates_count = 0;
  ret->pc_remote_ice_candidates_array_size = 0;
  ret->pc_candidate_pairs_sorted = NULL;
  ret->pc_candidate_pairs_count = 0;
  ret->pc_active_candidate_pair = -1;
  ret->pc_type = type;
  ret->pc_state = PCONN_STATE_WAIT_FOR_LOGIN;
  ret->pc_ice_gathering_state = PCONN_ICE_GATHERING_STATE_NEW;
  ret->pc_auth_attempts = 0;
  ret->pc_ice_role = ICE_ROLE_CONTROLLING;
  ret->pc_personaset = NULL;
  ret->pc_persona = NULL;
  ret->pc_sctp_capture.se_on_packet = pconn_on_sctp_packet;
  memset(&ret->pc_sctp_capture.se_source, 0, sizeof(ret->pc_sctp_capture.se_source));
  ret->pc_offer_line = 0;
  ret->pc_last_offer_line = -1;
  ret->pc_answer_offset = -1;

  ret->pc_outgoing_size = 0;
  ret->pc_outgoing_offs = 0;

  ret->pc_answer_flags = 0;
  ret->pc_answer_sctp = 0;
  ret->pc_remote_cert_fingerprint_digest = NULL;
  ret->pc_remote_ufrag[0] = '\0';
  ret->pc_remote_pwd[0] = '\0';

  ret->pc_tokens = NULL;
  ret->pc_apps = NULL;

  ret->pc_static_pkt_bio.bs_buf = ret->pc_incoming_pkt;
  BIO_STATIC_SET_READ_SZ(&ret->pc_static_pkt_bio, 0);

  if ( !RAND_bytes((unsigned char *)&ret->pc_tie_breaker, sizeof(ret->pc_tie_breaker)) ) {
    fprintf(stderr, "pconn_alloc: could not generate tie breaker\n");
    ERR_print_errors_fp(stderr);
  }

  // Set up sdp parser
  sdp_init(&ret->pc_answer_parser, pconn_sdp_new_media_fn,
           pconn_sdp_media_ctl_fn, pconn_sdp_attr_fn,
           (void *) ret);

  DLIST_ENTRY_CLEAR(&ret->pc_pconns_with_response_dl);

  // Collect all personas
  err = appstate_get_personaset(as, &ret->pc_personaset);
  if ( err < 0 ) {
    fprintf(stderr, "pconn_alloc: could not get personaset\n");
  }

  timersub_init_from_now(&ret->pc_timeout, PCONN_TIMEOUT, OP_PCONN_EXPIRES, pconn_fn);
  timersub_init_default(&ret->pc_conn_check_timer, OP_PCONN_CONN_CHECK_TIMER_RINGS, pconn_fn);
  timersub_init_default(&ret->pc_conn_check_timeout_timer, OP_PCONN_CONN_CHECK_TIMEOUT, pconn_fn);
  qdevtsub_init(&ret->pc_start_evt, OP_PCONN_STARTS, pconn_fn);
  qdevtsub_init(&ret->pc_new_token_evt, OP_PCONN_NEW_TOKEN, pconn_fn);

  return ret;
}

static void pconn_free(struct pconn *pc) {
  struct pconntoken *cur_pconntok, *tmp_pconntok;
  struct pconnapp *cur_pconnapp, *tmp_pconnapp;
  int i;

  fprintf(stderr, "pconn_free called\n");
  SAFE_MUTEX_LOCK(&pc->pc_mutex);

  HASH_ITER(pct_hh, pc->pc_tokens, cur_pconntok, tmp_pconntok) {
    HASH_DELETE(pct_hh, pc->pc_tokens, cur_pconntok);
    TOKEN_UNREF(cur_pconntok->pct_token);
    free(cur_pconntok);
  }
  HASH_CLEAR(pct_hh, pc->pc_tokens);

  HASH_ITER(pca_hh, pc->pc_apps, cur_pconnapp, tmp_pconnapp) {
    HASH_DELETE(pca_hh, pc->pc_apps, cur_pconnapp);

    container_release_running(&cur_pconnapp->pca_app->inst_container,
                              &pc->pc_appstate->as_eventloop);
    APPINSTANCE_UNREF(cur_pconnapp->pca_app);
    BRTUNNEL_UNREF(cur_pconnapp->pca_tun);
    free(cur_pconnapp);
  }
  HASH_CLEAR(pca_hh, pc->pc_apps);

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

  if ( pc->pc_local_ice_candidates ) {
    free(pc->pc_local_ice_candidates);
    pc->pc_local_ice_candidates = NULL;
    pc->pc_local_ice_candidates_count = 0;
    pc->pc_local_ice_candidates_array_size = 0;
  }

  if ( pc->pc_remote_ice_candidates ) {
    free(pc->pc_remote_ice_candidates);
    pc->pc_remote_ice_candidates = NULL;
    pc->pc_remote_ice_candidates_count = 0;
    pc->pc_remote_ice_candidates_array_size = 0;
  }

  if ( pc->pc_candidate_pairs_count > 0 ) {
    for ( i = 0; i < pc->pc_candidate_pairs_count; ++i )
      free(pc->pc_candidate_pairs_sorted[i]);
    free(pc->pc_candidate_pairs_sorted);
    pc->pc_candidate_pairs_sorted = NULL;
    pc->pc_candidate_pairs_count = 0;
    pc->pc_candidate_pair_pending_ix = -1;
  }

  if ( pc->pc_dtls ) {
    SSL_free(pc->pc_dtls);
    pc->pc_dtls = NULL;
  }

  pthread_mutex_unlock(&pc->pc_mutex);

  pthread_mutex_destroy(&pc->pc_mutex);
  free(pc);
}

void pconn_set_request(struct pconn *pc, uint16_t req, const struct stuntxid *id) {
  SAFE_MUTEX_LOCK(&pc->pc_mutex);
  memcpy(&pc->pc_tx_id, id, sizeof(pc->pc_tx_id));
  pc->pc_last_req = req;
  pthread_mutex_unlock(&pc->pc_mutex);
}

void pconn_start_service(struct pconn *pc) {
  PCONN_WREF(pc);
  eventloop_subscribe_timer(&pc->pc_appstate->as_eventloop, &pc->pc_timeout);

  PCONN_WREF(pc);
  eventloop_queue(&pc->pc_appstate->as_eventloop, &pc->pc_start_evt);
}

#define OFFER_LINE_START if (1) {                                       \
    struct stunattr* next_attr;                                         \
    prev_attr = *attr;                                                  \
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
      *attr = prev_attr;                                                \
      ret = -1;                                                         \
      fprintf(stderr, "pconn_write_offer: no more space in line\n");    \
      break;                                                            \
    }                                                                   \
    line_off += err;                                                    \
  }
#define OFFER_LINE_END if(1) {                                          \
    STUN_INIT_ATTR(*attr, STUN_ATTR_KITE_SDP_LINE, sizeof(uint16_t) + line_off); \
    if ( !STUN_ATTR_IS_VALID(*attr, msg, buf_sz) ) {                    \
      *attr = prev_attr;                                                \
      break;                                                            \
    }                                                                   \
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
  kite_sock_addr addr;
  char *addrty;
  int ret = -1, err, line_off = 0, i, did_complete_line = 0;
  unsigned int digest_len = SHA256_DIGEST_LENGTH;
  //  socklen_t addrsz = sizeof(addr);
  X509 *cert;
  unsigned char digest[SHA256_DIGEST_LENGTH];
  struct stunattr *prev_attr = *attr;

//  err = getsockname(pc->pc_socket, &addr, &addrsz);
//  if ( err < 0 ) {
//    perror("pconn_write_offer: getsockname");
  addr.ksa.sa_family = AF_UNSPEC;// TODO
    //  }

  switch ( addr.ksa.sa_family ) {
  case AF_INET:
    addrty = "IP4";
    inet_ntop(AF_INET, &((struct sockaddr_in *)&addr)->sin_addr, addr_buf, sizeof(addr_buf));
    break;
  case AF_INET6:
    addrty = "IP6";
    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&addr)->sin6_addr, addr_buf, sizeof(addr_buf));
    break;
  default:
    addrty = "IP4";
    strncpy(addr_buf, "127.0.0.1", sizeof(addr_buf));
    break;
  }

  switch ( pc->pc_offer_line ) {
  case 0: OFFER_LINE("v=0");
  case 1:
    OFFER_LINE("o=- %u 2 IN %s %s", (unsigned int)(((uintptr_t)pc->pc_conn_id) & 0xFFFFFFFF),
               addrty, addr_buf)
  case 2:
    OFFER_LINE("s=-");
  case 3:
    OFFER_LINE("t=0 0");
  case 4:
    OFFER_LINE("a=group:BUNDLE " PCONN_DATACHANNEL_MID);
  case 5:
    OFFER_LINE("a=msid-semantic: WMS");
  case 6:
    OFFER_LINE("m=application 9 DTLS/SCTP webrtc-datachannel");
  case 7:
    OFFER_LINE("c=IN %s %s", addrty, addr_buf);
  case 8:
    OFFER_LINE("a=max-message-size:%d", PCONN_MAX_MESSAGE_SIZE);
  case 9:
    OFFER_LINE("a=sctpmap:%d webrtc-datachannel %d", pc->pc_sctp_port, PCONN_MAX_SCTP_STREAMS);
  case 10:
    OFFER_LINE("a=sctp-port:%d", pc->pc_sctp_port);
  case 11:
    OFFER_LINE("a=ice-options:trickle");
  case 12:
    OFFER_LINE("a=setup:actpass"); // TODO allow actpass
  case 13:
    OFFER_LINE("a=mid:" PCONN_DATACHANNEL_MID);
  case 14:
    OFFER_LINE("a=ice-ufrag:%.*s", (int) sizeof(pc->pc_our_ufrag), pc->pc_our_ufrag);
  case 15:
    OFFER_LINE("a=ice-pwd:%.*s", (int) sizeof(pc->pc_our_pwd), pc->pc_our_pwd);
  case 16: // If you change this, be sure to change 15 below
    OFFER_LINE_START;
    cert = appstate_get_certificate(pc->pc_appstate);
    if ( !cert ) return -1;

    err = X509_digest(cert, EVP_sha256(), digest, &digest_len);
    X509_free(cert);
    if ( err == 0 ) {
      return -1;
    }

    if ( digest_len != sizeof(digest) ) return -1;

    OFFER_WRITE("a=fingerprint:sha-256");
    for ( i = 0; i < sizeof(digest); ++i )
      OFFER_WRITE("%c%02X", i == 0 ? ' ' : ':',
                  digest[i]);

    OFFER_LINE_END;

    // Always keep this before default:
    pc->pc_last_offer_line = pc->pc_offer_line;
  default: // Do not separate above line

    if ( pc->pc_offer_line > 0 ) {
      for ( i = pc->pc_offer_line - pc->pc_last_offer_line;
            i < pc->pc_local_ice_candidates_count;
            ++i ) {
        did_complete_line = 0;
        OFFER_LINE_START;
        OFFER_WRITE("a=");
        FORMAT_ICE_CANDIDATE(&pc->pc_local_ice_candidates[i], OFFER_WRITE);
        OFFER_LINE_END;
        did_complete_line = 1;
      }

      if ( !did_complete_line ) break;
    }

    if ( pc->pc_offer_line != -1 ) { // Once pc_offer_line is -1, there are no more lines
      if ( pc->pc_ice_gathering_state == PCONN_ICE_GATHERING_STATE_COMPLETE )
        pc->pc_offer_line = -1; // Mark done
      else
        pc->pc_offer_line = -2; // Mark almost done

      fprintf(stderr, "Marked pc_offer_line %d\n", pc->pc_offer_line);
      OFFER_LINE_START;
      OFFER_LINE_END;
    }
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

  switch ( pc->pc_state ) {
  case PCONN_STATE_WAIT_FOR_LOGIN:
  case PCONN_STATE_START_OFFER:
    STUN_INIT_MSG(msg, STUN_RESPONSE | STUN_KITE_STARTCONN);
    memcpy(&msg->sm_tx_id, &pc->pc_tx_id, sizeof(msg->sm_tx_id));

    STUN_ADD_CONNECTION_ID;

    if ( pc->pc_personaset ) {
      attr = STUN_NEXTATTR(attr);
      if ( !STUN_IS_VALID(attr, msg, buf_sz) ) return -1;
      STUN_INIT_ATTR(attr, STUN_ATTR_KITE_PERSONAS_HASH, SHA256_DIGEST_LENGTH);
      if ( !STUN_ATTR_IS_VALID(attr, msg, buf_sz) ) return -1;
      memcpy((char *) STUN_ATTR_DATA(attr), pc->pc_personaset->ps_hash, SHA256_DIGEST_LENGTH);
    }

    STUN_FINISH_WITH_FINGERPRINT(attr, msg, buf_sz, ret);
    break;

  case PCONN_STATE_SENDING_OFFER:
    fprintf(stderr, "pconn_respond: sending offer\n");
    // We've successfully sent the connection start the offer
    STUN_INIT_MSG(msg, STUN_RESPONSE | STUN_KITE_SENDOFFER);
    memcpy(&msg->sm_tx_id, &pc->pc_tx_id, sizeof(msg->sm_tx_id));
    STUN_ADD_CONNECTION_ID;

    // Add the answer offset if we'd like
    if ( pc->pc_answer_offset >= 0 ) {
      uint16_t offs16 = pc->pc_answer_offset > 0xFFFF ? 0xFFFF : pc->pc_answer_offset;
      offs16 = htons(offs16);

      attr = STUN_NEXTATTR(attr);
      if ( !STUN_IS_VALID(attr, msg, buf_sz) ) return -1;
      STUN_INIT_ATTR(attr, STUN_ATTR_KITE_ANSWER_OFFSET, sizeof(uint16_t));
      if ( !STUN_ATTR_IS_VALID(attr, msg, buf_sz) ) return -1;
      memcpy(STUN_ATTR_DATA(attr), &offs16, sizeof(uint16_t));
    }

    if ( pc->pc_offer_line != -1 ) {
      if ( pconn_write_offer(pc, msg, &attr, buf_sz - STUN_FINGERPRINT_GAP) < 0 )
        ret = -1;
    }

    if ( ret != -1 ) {
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
  int old_subs, i;

  fprintf(stderr, "pconn_finish!!!\n");

  if ( eventloop_cancel_timer(&pc->pc_appstate->as_eventloop, &pc->pc_conn_check_timer) ) {
    PCONN_WUNREF(pc);
  }

  if ( eventloop_cancel_timer(&pc->pc_appstate->as_eventloop, &pc->pc_timeout) )
    PCONN_WUNREF(pc);

  SHARED_DEBUG(&pc->pc_shared, "after cancel timers");

  for ( i = 0; i < pc->pc_candidate_sources_count; ++i ) {
    struct candsrc *src = &pc->pc_candidate_sources[i];

    old_subs = eventloop_unsubscribe_fd(&pc->pc_appstate->as_eventloop, src->cs_socket,
                                        FD_SUB_ALL, &src->cs_socket_sub);

    if ( old_subs & FD_SUB_READ )
      PCONN_WUNREF(pc);
    if ( old_subs & FD_SUB_ERROR )
      PCONN_WUNREF(pc);

  }

  SHARED_DEBUG(&pc->pc_shared, "after events unregister");
  flock_pconn_expires(pc->pc_flock, pc);
  SHARED_DEBUG(&pc->pc_shared, "after expiration");
}

static void pconn_auth_fails(struct pconn *pc) {
  if ( !PCONN_IS_ERRORED(pc) ) {
    pc->pc_state = PCONN_STATE_ERROR_AUTH_FAILED;
    pc->pc_auth_attempts ++;

    if ( pc->pc_auth_attempts >= PCONN_MAX_AUTH_ATTEMPTS)
      pconn_finish(pc);
  }
}

void pconn_process_sdp_answer(struct pconn *pc, const char *buf, size_t bytes) {
  int err;

  fprintf(stderr, "process_sdp_answer: %.*s\n", (int)bytes, buf);

  err = sdp_parse(&pc->pc_answer_parser, buf, bytes);
  if ( err != SPS_SUCCESS && err != SPS_PARSE_MORE ) {
    fprintf(stderr, "SDP parser fails with (%d:%d): %d\n", pc->pc_answer_parser.sps_line_num, pc->pc_answer_parser.sps_column_pos, err);
    pc->pc_state = PCONN_STATE_ERROR_BAD_ANSWER;
  } else
    fprintf(stderr, "Sdp buffer parsed successfully\n");
}

void pconn_recv_sendoffer(struct pconn *pc, int line,
                          const char *answer, uint16_t answer_offs, size_t answer_sz) {
  PCONN_REF(pc);
  SAFE_MUTEX_LOCK(&pc->pc_mutex);

  fprintf(stderr, "Got send offer request\n");

  if ( pc->pc_state == PCONN_STATE_START_OFFER )
    pc->pc_state = PCONN_STATE_SENDING_OFFER;

  if ( line <= pc->pc_offer_line ) {
    pc->pc_offer_line = line;

    if ( pc->pc_last_offer_line > 0 &&
         line >= (pc->pc_last_offer_line + pc->pc_local_ice_candidates_count) ) {
      // The last offer line was written
      fprintf(stderr, "pconn_recv_sendoffer: got request for line %d, but there's no more lines\n", line);
    } else {
      flock_request_pconn_write_unlocked(pc->pc_flock, pc);
    }
  }

  if ( answer_sz > 0 ) {
    uint16_t next_offset = answer_offs + answer_sz;

    fprintf(stderr, "Got send offer request with answer %zu\n", answer_sz);

    if ( next_offset > pc->pc_answer_offset ) {
      if ( pc->pc_answer_offset < 0 ) {
        sdp_reset(&pc->pc_answer_parser);
        pc->pc_answer_offset = 0;
      }

      if ( answer_offs <= pc->pc_answer_offset &&
           (pc->pc_answer_offset - answer_offs) < answer_sz ) {

        pconn_process_sdp_answer(pc, answer + pc->pc_answer_offset - answer_offs,
                                 answer_sz + answer_offs - pc->pc_answer_offset);

        pc->pc_answer_offset = next_offset;
      }
    }
    flock_request_pconn_write_unlocked(pc->pc_flock, pc);
  }

  pthread_mutex_unlock(&pc->pc_mutex);
  PCONN_UNREF(pc);
}

void pconn_recv_startconn(struct pconn *pc, const char *persona_id,
                          const char *credential, size_t cred_sz) {
  PCONN_REF(pc);
  SAFE_MUTEX_LOCK(&pc->pc_mutex);

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
        if ( persona_credential_validates(p, pc, credential, cred_sz) != 1 ) {
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

static void pconn_ice_gathering_state_may_change(struct pconn *pc) {
  int i, all_done = 1, any_fail = 0;
  int old_state = pc->pc_ice_gathering_state, new_state = PCONN_ICE_GATHERING_STATE_GATHERING;

  for ( i = 0; i < pc->pc_candidate_sources_count; ++i ) {
    struct candsrc *cs = &pc->pc_candidate_sources[i];
    if ( cs->cs_state != CS_STATE_DONE &&
         cs->cs_state != CS_STATE_KEEPALIVE &&
         cs->cs_state != CS_STATE_ERROR ) {
      fprintf(stderr, "pconn_ice_gathering_state_may_change: candidate %d of %d is not done\n", i,
              pc->pc_candidate_sources_count);
      all_done = 0;
    } else
      fprintf(stderr, "pconn_ice_gathering_state_may_change: candidate %d of %d is done\n", i,
              pc->pc_candidate_sources_count);

    if ( cs->cs_state != CS_STATE_ERROR )
      any_fail = 1;
  }

  if ( all_done )
    new_state = PCONN_ICE_GATHERING_STATE_COMPLETE;

  if ( any_fail ) {
    fprintf(stderr, "Pconn: some candidates failed\n");
  }

  if ( new_state != old_state ) {
    pc->pc_ice_gathering_state = new_state;
  }
}

static int pconn_cs_idx(struct pconn *pc, struct candsrc *cs) {
  int ix;

  ix = cs - pc->pc_candidate_sources;

  if ( ix > pc->pc_candidate_sources_count )
    return -1;

  return ix;
}

static int dbgprintf(const char *format, ...) {
  va_list v;
  int ret;

  va_start(v, format);
  ret = vfprintf(stderr, format, v);
  va_end(v);

  return ret;
}

static void pconn_candpair_activated(struct pconn *pc) {
  fprintf(stderr, "pconn_candpair_activated: TODO\n");

  // What should happen here is that we transfer all candidate sources to an established
  // connection, unset the pc_timeout. Get rid of pc_personaset, pc_answer_parser,
  // pc_candidate_pairs, pc_local_ice_candidates, pc_remote_ice_candidates. All
  // pc_candidate_sources except the active one, etc.
  if ( eventloop_cancel_timer(&pc->pc_appstate->as_eventloop, &pc->pc_timeout) )
    PCONN_WUNREF(pc);

  if ( pc->pc_personaset ) {
    PERSONASET_UNREF(pc->pc_personaset);
    pc->pc_personaset = NULL;
  }

  pc->pc_state = PCONN_STATE_DTLS_STARTING;

  // Launch persona container, and start routing traffic throug
}

static void pconn_activate_best_pair(struct pconn *pc) {
  int i;

  for ( i = 0; i < pc->pc_candidate_pairs_count; ++i )
    if ( ICECANDPAIR_SUCCESS(pc->pc_candidate_pairs_sorted[i]) ) {
      break;
    }

  if ( i < pc->pc_candidate_pairs_count ) {
    if ( pc->pc_active_candidate_pair < 0 ) {
      struct icecandpair *new_pair;

      pc->pc_active_candidate_pair = i;
      fprintf(stderr, "pconn_connectivity_check_succeeds: activating pair %d\n", i);
      pconn_candpair_activated(pc);

      fprintf(stderr, "active pair is\n  Local: ");
      new_pair = pc->pc_candidate_pairs_sorted[i];
      FORMAT_ICE_CANDIDATE(&pc->pc_local_ice_candidates[ new_pair->icp_local_ix ], dbgprintf);
      fprintf(stderr, "(cs ix: %d)\n  Remote: ",pc->pc_local_ice_candidates[ new_pair->icp_local_ix ].ic_candsrc_ix);
      FORMAT_ICE_CANDIDATE(&pc->pc_remote_ice_candidates[ new_pair->icp_remote_ix ], dbgprintf);
    } else
      pc->pc_active_candidate_pair = i;
  }
}

static void pconn_connectivity_check_succeeds(struct pconn *pc, int cand_pair_ix, int flag) {
  struct icecandpair *pair;

  if ( cand_pair_ix < 0 || cand_pair_ix >= pc->pc_candidate_pairs_count ) {
    fprintf(stderr, "pconn_connectivity_check_succeeds: invalid index\n");
    return;
  }

  if ( pc->pc_active_candidate_pair > 0 &&
       pc->pc_active_candidate_pair == cand_pair_ix ) {
    // reset timeout timer
    pconn_reset_connectivity_check_timeout(pc);
  } else if ( pc->pc_active_candidate_pair < 0 ) {
    pair = pc->pc_candidate_pairs_sorted[cand_pair_ix];

    if ( !pair ) {
      fprintf(stderr, "pconn_connectivity_check_succeeds: invalid pair %d\n", cand_pair_ix);
      return;
    }

    stun_random_tx_id(&pair->icp_tx_id); // Generate new TX id

    fprintf(stderr, "Connectivity check succeeds on candidate pair %d: %08x\n", cand_pair_ix, flag);
    pair->icp_flags |= flag;

    if ( ICECANDPAIR_SUCCESS(pair) ) {
      pconn_activate_best_pair(pc);
    }
  }
}

static void pconn_reset_connectivity_check_timer(struct pconn *pc) {
  if ( !eventloop_cancel_timer(&pc->pc_appstate->as_eventloop, &pc->pc_conn_check_timer) ) {
    PCONN_WREF(pc);
  }
  if ( pc->pc_state == PCONN_STATE_ESTABLISHED ) {
    timersub_set_from_now(&pc->pc_conn_check_timer, PCONN_CONNECTIVITY_CHECK_CONNECTED_INTERVAL);
  } else if ( pc->pc_state != PCONN_STATE_DISCONNECTED ) {
    timersub_set_from_now(&pc->pc_conn_check_timer, PCONN_CONNECTIVITY_CHECK_INTERVAL);
  }
  eventloop_subscribe_timer(&pc->pc_appstate->as_eventloop, &pc->pc_conn_check_timer);
}

static void pconn_reset_connectivity_check_timeout(struct pconn *pc) {
  eventloop_dbg_verify_timers(&pc->pc_appstate->as_eventloop);
  if ( !eventloop_cancel_timer(&pc->pc_appstate->as_eventloop, &pc->pc_conn_check_timeout_timer) ) {
    PCONN_WREF(pc);
  }

  timersub_set_from_now(&pc->pc_conn_check_timeout_timer,
                        PCONN_CONNECTIVITY_CHECK_TIMEOUT);
  eventloop_subscribe_timer(&pc->pc_appstate->as_eventloop, &pc->pc_conn_check_timeout_timer);
}

static int cmp_candidates(const void *app, const void *bpp) {
  const struct icecandpair *const *ap = app, *const *bp = bpp;

  if ( (*ap)->icp_priority < (*bp)->icp_priority )
    return 1; // Sort descending
  else if ( (*ap)->icp_priority > (*bp)->icp_priority )
    return -1;
  else
    return 0;
}

static int pconn_form_candidate_pairs(struct pconn *pc, struct icecand *cand, int cand_type) {
  struct icecandpair **pairs = pc->pc_candidate_pairs_sorted;
  struct icecand *potential_partners;
  int potential_partners_count, i, partners_to_add = 0, cur_pair;
  int initial_candidates_count = pc->pc_candidate_pairs_count;
  int cand_ix;

  switch ( cand_type ) {
  case PCONN_LOCAL_CANDIDATE:
    potential_partners = pc->pc_remote_ice_candidates;
    potential_partners_count = pc->pc_remote_ice_candidates_count;
    cand_ix = cand - pc->pc_local_ice_candidates;
    if ( cand_ix >= pc->pc_local_ice_candidates_count ) {
      fprintf(stderr, "pconn_form_candidate_pairs: %p is not a valid local candidate\n", cand);
      return -1;
    }
    break;
  case PCONN_REMOTE_CANDIDATE:
    potential_partners = pc->pc_local_ice_candidates;
    potential_partners_count = pc->pc_local_ice_candidates_count;
    cand_ix = cand - pc->pc_remote_ice_candidates;
    if ( cand_ix >= pc->pc_remote_ice_candidates_count ) {
      fprintf(stderr, "pconn_form_candidate_pairs: %p is not a valid remote candidate\n", cand);
      return -1;
    }
    break;

  default:
    abort();
  }

  for ( i = 0; i < potential_partners_count; ++i )
    if ( ICECAND_CAN_PAIR(cand, &potential_partners[i]) )
      partners_to_add++;

  if ( partners_to_add == 0 ) {
    fprintf(stderr, "pconn_form_candidate_pairs: no pairs to add\n");
    return 0;
  }

  pairs = realloc(pairs, (pc->pc_candidate_pairs_count + partners_to_add) * sizeof(struct icecandpair*));
  if ( !pairs ) {
    fprintf(stderr, "pconn_form_candidate_pairs: out of memory\n");
    return -1;
  }

  pc->pc_candidate_pairs_sorted = pairs;

  for ( i = 0, cur_pair = pc->pc_candidate_pairs_count; i < potential_partners_count; ++i )
    if ( ICECAND_CAN_PAIR(cand, &potential_partners[i]) ) {
      pairs[cur_pair] = malloc(sizeof(struct icecandpair));
      if ( !pairs[cur_pair] ) {
        fprintf(stderr, "pconn_form_candidate_pairs: out of memory\n");
        return -1;
      }

      pairs[cur_pair]->icp_flags = 0;

      if ( cand_type == PCONN_LOCAL_CANDIDATE ) {
        pairs[cur_pair]->icp_local_ix = cand_ix;
        pairs[cur_pair]->icp_remote_ix = i;
      } else {
        pairs[cur_pair]->icp_remote_ix = cand_ix;
        pairs[cur_pair]->icp_local_ix = i;
      }
      stun_random_tx_id(&pairs[cur_pair]->icp_tx_id);
      pairs[cur_pair]->icp_priority = icecand_pair_priority(pc, &pc->pc_local_ice_candidates[ pairs[cur_pair]->icp_local_ix ],
                                                            &pc->pc_remote_ice_candidates[ pairs[cur_pair]->icp_remote_ix ]);

      fprintf(stderr, "Added pair %d with priority %"PRIu64":\n  Local:", cur_pair, pairs[cur_pair]->icp_priority);
      FORMAT_ICE_CANDIDATE(&pc->pc_local_ice_candidates[ pairs[cur_pair]->icp_local_ix ], dbgprintf);
      fprintf(stderr, "(cs ix: %d)\n  Remote:", pc->pc_local_ice_candidates[ pairs[cur_pair]->icp_local_ix ].ic_candsrc_ix);
      FORMAT_ICE_CANDIDATE(&pc->pc_remote_ice_candidates[ pairs[cur_pair]->icp_remote_ix ], dbgprintf);
      fprintf(stderr, "\n");
      cur_pair++;
    }

  pc->pc_candidate_pairs_count += partners_to_add;

  if ( partners_to_add > 0 ) {
    fprintf(stderr, "Sorting candidates\n");
    qsort(pc->pc_candidate_pairs_sorted, pc->pc_candidate_pairs_count,
          sizeof(*pc->pc_candidate_pairs_sorted), cmp_candidates);

    if ( initial_candidates_count == 0 ) {
      pc->pc_candidate_pair_pending_ix = 0;
      pconn_reset_connectivity_check_timer(pc);
    }
  }

  return 0;
}

static int pconn_add_ice_candidate(struct pconn *pc, int cand_type, struct icecand *cand) {
  struct icecand *cur_cands;
  int cur_cands_cnt, cur_cands_asize, i, ret = 0;

  switch ( cand_type ) {
  case PCONN_LOCAL_CANDIDATE:
    cur_cands = pc->pc_local_ice_candidates;
    cur_cands_cnt = pc->pc_local_ice_candidates_count;
    cur_cands_asize = pc->pc_local_ice_candidates_array_size;

    if ( cand->ic_candsrc_ix < 0 )
      return -1;

    break;
  case PCONN_REMOTE_CANDIDATE:
    cur_cands = pc->pc_remote_ice_candidates;
    cur_cands_cnt = pc->pc_remote_ice_candidates_count;
    cur_cands_asize = pc->pc_remote_ice_candidates_array_size;
    break;
  default:
    abort();
  }

  // Check to see if the candidate already exists
  for ( i = 0; i < cur_cands_cnt; ++i ) {
    if ( icecand_equivalent(&cur_cands[i], cand) ) {
      return 0; // Already exists
    }
  }

  if ( cur_cands_cnt >= PCONN_MAX_CANDIDATES ) {
    fprintf(stderr, "pconn_add_ice_candidate: more than PCONN_MAX_CANDIDATES reached\n");
    return -1;
  }

  // Otherwise attempt to add
  if ( cur_cands_cnt == cur_cands_asize ) {
    struct icecand *new;

    if ( cur_cands_asize == 0 ) cur_cands_asize = 4;
    else cur_cands_asize *= 2;

    new = realloc(cur_cands, cur_cands_asize * sizeof(*new));
    if ( !new ) return -1;

    cur_cands = new;
  }

  memcpy(&cur_cands[cur_cands_cnt], cand, sizeof(cur_cands[cur_cands_cnt]));
  cur_cands[cur_cands_cnt].ic_priority = icecand_recommend_priority(&cur_cands[cur_cands_cnt], 0);

  STATIC_ASSERT(ICE_FOUNDATION_LEN < (sizeof(cur_cands[cur_cands_cnt].ic_foundation) / sizeof(cur_cands[cur_cands_cnt].ic_foundation[0])),
                "ICE_FOUNDATION_LEN must be less than the size of ic_foundation");

  if ( cand_type == PCONN_LOCAL_CANDIDATE ) {
    if ( !random_printable_string(cur_cands[cur_cands_cnt].ic_foundation, ICE_FOUNDATION_LEN) ) {
      ret = -1;
    }
    cur_cands[cur_cands_cnt].ic_foundation[ICE_FOUNDATION_LEN] = '\0';
  } else
    cur_cands[cur_cands_cnt].ic_candsrc_ix = -1;


  if ( ret >= 0 ) {
    if ( cur_cands[cur_cands_cnt].ic_transport != IPPROTO_UDP &&
         cur_cands[cur_cands_cnt].ic_transport != IPPROTO_TCP )
      ret = -1;
    else {
      ret = 1;
      cur_cands_cnt++;

      fprintf(stderr, "pconn_add_ice_candidate: %s\n",
              cand_type == PCONN_LOCAL_CANDIDATE ? "local" : "remote");
      FORMAT_ICE_CANDIDATE(&cur_cands[cur_cands_cnt - 1], dbgprintf);
      fprintf(stderr, "\n");
    }
  }

  switch ( cand_type ) {
  case PCONN_LOCAL_CANDIDATE:
    pc->pc_local_ice_candidates = cur_cands;
    pc->pc_local_ice_candidates_count = cur_cands_cnt;
    pc->pc_local_ice_candidates_array_size = cur_cands_asize;
    break;
  case PCONN_REMOTE_CANDIDATE:
    pc->pc_remote_ice_candidates = cur_cands;
    pc->pc_remote_ice_candidates_count = cur_cands_cnt;
    pc->pc_remote_ice_candidates_array_size = cur_cands_asize;
    break;
  default:
    abort();
  }

  if ( ret >= 0 ) {
    // Now form candidate pairs and prioritize
    if ( pconn_form_candidate_pairs(pc, &cur_cands[cur_cands_cnt - 1], cand_type) < 0 )
      ret = -1;
  }

  return ret;
}

static struct icecandpair *pconn_find_candidate_pair(struct pconn *pc, struct candsrc *src,
                                                     struct sockaddr *peer_addr, size_t peer_addr_sz,
                                                     int *icp_ix) {
  int i = 0, cs_idx = pconn_cs_idx(pc, src);

  if( cs_idx < 0 ) {
    fprintf(stderr, "pconn_find_candidate_pair: invalid candsrc\n");
    if ( icp_ix ) *icp_ix = -1;
    return NULL;
  }

  //  fprintf(stderr, "asked to find binding request  for cs idx %d\n", cs_idx);

  for ( i = 0; i < pc->pc_candidate_pairs_count; ++i ) {
    struct icecand *local = &pc->pc_local_ice_candidates[ pc->pc_candidate_pairs_sorted[i]->icp_local_ix ];
    if ( local->ic_candsrc_ix == cs_idx ) {
      struct icecand *remote = &pc->pc_remote_ice_candidates[ pc->pc_candidate_pairs_sorted[i]->icp_remote_ix ];
//      fprintf(stderr, "Check remote equal (local ix is %d) ", cs_idx);
//      dump_address(stderr, peer_addr, peer_addr_sz);
//      fprintf(stderr, " == ");
//      dump_address(stderr, &remote->ic_addr, sizeof(remote->ic_addr));
//      fprintf(stderr, "\n");
      // Check if the remote candidate matches this one
      if ( kite_sock_addr_equal(&remote->ic_addr, peer_addr, peer_addr_sz) ) {
        if ( icp_ix ) *icp_ix = i;
        return pc->pc_candidate_pairs_sorted[i];
      }
    }
  }

  if ( icp_ix ) *icp_ix = -1;
  return NULL;
}

static const char *ice_transport_str(int ts) {
  switch (ts) {
  case IPPROTO_UDP: return "udp";
  case IPPROTO_TCP: return "tcp";
  default: return "unknown";
  }
}

static const char *ice_type_str(int ty) {
  switch (ty) {
  case ICE_TYPE_HOST:  return "host";
  case ICE_TYPE_SRFLX: return "srflx";
  case ICE_TYPE_PRFLX: return "prflx";
  case ICE_TYPE_RELAY: return "relay";
  default: return "unknown";
  }
}

static uint32_t icecand_recommend_priority(struct icecand *ic, uint16_t local_pref) {
  uint32_t pt = (((uint32_t) local_pref) << 8) | ic->ic_component;
  uint8_t type_preference = 0;
  switch ( ic->ic_type ) {
  case ICE_TYPE_HOST:  type_preference = 126; break;
  case ICE_TYPE_PRFLX: type_preference = 110; break;
  case ICE_TYPE_SRFLX: type_preference = 100; break;
  default:
  case ICE_TYPE_RELAY: type_preference = 0; break;
  }

  return pt | (((uint32_t) type_preference) << 24);
}

#define ICECAND_PRINT_POS                                               \
  fprintf(stderr, "icecand_parse: at %d\n", (int)(start - start_init));
#define ICECAND_PEEK(str)                                               \
  ( (end - start) >= strlen(str) &&                                     \
    ( strncasecmp(start, (str), strlen(str)) == 0 ?                     \
      (start += strlen(str), 1) : 0) )
#define ICECAND_EXACT(str) do {                                         \
    if ( !(ICECAND_PEEK(str)) ) {                                       \
      fprintf(stderr, "icecand_parse: expected \"" str "\"\n");         \
      ICECAND_PRINT_POS;                                                \
      return -1;                                                        \
    }                                                                   \
  } while (0)
#define ICECAND_PARSE_FIELD(fld, sz) do {                               \
    int __i_ ## __LINE__;                                               \
    for ( __i_ ## __LINE__ = 0;                                         \
          __i_ ## __LINE__ < ((sz) - 1) && !isspace(*start);            \
          __i_ ## __LINE__ ++, start++)                                 \
      (fld)[__i_ ## __LINE__] = *start;                                 \
                                                                        \
    if ( __i_ ## __LINE__ >= ((sz) - 1) ) {                             \
      fprintf(stderr, "icecand_parse: not enough space for ICECAND_PARSE_FIELD\n"); \
      ICECAND_PRINT_POS;                                                \
      return -1;                                                        \
    }                                                                   \
                                                                        \
    (fld)[__i_ ## __LINE__] = '\0';                                     \
  } while(0)
#define ICECAND_PARSE_DECIMAL(i) do {                                   \
    int __dec_ ## __LINE__;                                             \
    int __read_ ## __LINE__ =                                           \
      parse_decimal(&__dec_ ## __LINE__, start, (int) (end - start));   \
    if ( __read_ ## __LINE__ <= 0 ) {                                   \
      fprintf(stderr, "icecand_parse: not enough characters in decimal\n"); \
      ICECAND_PRINT_POS;                                                \
      return -1;                                                        \
    }                                                                   \
    (i) = __dec_ ## __LINE__;                                           \
    start += __read_ ## __LINE__;                                       \
  } while (0)
#define ICECAND_TOKEN do {                                              \
    if ( start != end && !isspace(*start) ) {                           \
      fprintf(stderr, "icecand_parse: expected space or end of line\n"); \
      ICECAND_PRINT_POS;                                                \
      return -1;                                                        \
    }                                                                   \
    for ( ; isspace(*start) && start != end; ++start );                 \
  } while(0)
static int icecand_parse(struct icecand *ic, const char *start, const char *end) {
  char ip_addr[INET6_ADDRSTRLEN];
  uint16_t port;
  socklen_t addr_sz;
  const char *start_init = start;

  if ( start == end ) return -1;

  ICECAND_PARSE_FIELD(ic->ic_foundation, sizeof(ic->ic_foundation));
  ICECAND_TOKEN;

  ICECAND_PARSE_DECIMAL(ic->ic_component);
  ICECAND_TOKEN;

  if ( ICECAND_PEEK("udp") ) {
    ic->ic_transport = IPPROTO_UDP;
  } else if ( ICECAND_PEEK("tcp") ) {
    ic->ic_transport = IPPROTO_TCP;
  } else {
    fprintf(stderr, "icecand_parse: expected udp or tcp as proto\n");
    fprintf(stderr, "Got %.*s\n", (int)(end - start), start);
    ICECAND_PRINT_POS;
    return -1;
  }

  ICECAND_TOKEN;

  ICECAND_PARSE_DECIMAL(ic->ic_priority);
  ICECAND_TOKEN;

  ICECAND_PARSE_FIELD(ip_addr, sizeof(ip_addr));
  ICECAND_TOKEN;

  ICECAND_PARSE_DECIMAL(port);
  ICECAND_TOKEN;

  addr_sz = sizeof(ic->ic_addr);
  if ( parse_address(ip_addr, sizeof(ip_addr), port,
                     &ic->ic_addr.ksa, &addr_sz) < 0 ) {
    fprintf(stderr, "icecand_parse: could not parse address\n");
    return -1;
  }

  ICECAND_EXACT("typ");
  ICECAND_TOKEN;

  if ( ICECAND_PEEK("host") ) ic->ic_type = ICE_TYPE_HOST;
  else if ( ICECAND_PEEK("srflx") ) ic->ic_type = ICE_TYPE_SRFLX;
  else if ( ICECAND_PEEK("prflx") ) ic->ic_type = ICE_TYPE_PRFLX;
  else if ( ICECAND_PEEK("relay") ) ic->ic_type = ICE_TYPE_RELAY;
  else {
    fprintf(stderr, "icecand_parse: expected host, srflx, prflx, or relay\n");
    return -1;
  }
  ICECAND_TOKEN;

  if ( ic->ic_type != ICE_TYPE_HOST ) {
    ICECAND_EXACT("raddr");
    ICECAND_TOKEN;

    ICECAND_PARSE_FIELD(ip_addr, sizeof(ip_addr));
    ICECAND_TOKEN;

    ICECAND_EXACT("rport");
    ICECAND_TOKEN;

    ICECAND_PARSE_DECIMAL(port);
    ICECAND_TOKEN;

    addr_sz = sizeof(ic->ic_raddr);
    if ( parse_address(ip_addr, sizeof(ip_addr), port,
                       &ic->ic_raddr.ksa, &addr_sz) < 0 ) {
      fprintf(stderr, "icecand_parse: could not parse raddr\n");
      return -1;
    }
  }

  return 0;
}

static int pconn_sdp_new_media_fn(void *pc_) {
  struct pconn *pc = (struct pconn *) pc_;

  if ( (pc->pc_answer_flags & PCONN_ANSWER_IN_MEDIA_STREAM) &&
       (pc->pc_answer_flags & PCONN_ANSWER_IN_DATA_CHANNEL) == 0 &&
       (pc->pc_answer_flags & PCONN_ANSWER_DAT_CHAN_CREATD) == 0 ) {
    // We read a channel, but it's not the data one... ignore
    pc->pc_answer_flags &= ~(PCONN_ANSWER_HAS_UFRAG | PCONN_ANSWER_HAS_PASSWORD |
                             PCONN_ANSWER_ICE_TRICKLE | PCONN_ANSWER_HAS_FINGERPRINT |
                             PCONN_ANSWER_IS_ACTIVE | PCONN_ANSWER_IS_PASSIVE |
                             PCONN_ANSWER_HAS_SCTP_PORT);
    pc->pc_remote_ufrag[0] = '\0';
    pc->pc_remote_pwd[0] = '\0';
    pc->pc_answer_sctp = 0;
  }

  pc->pc_answer_flags |= PCONN_ANSWER_IN_MEDIA_STREAM;
  pc->pc_answer_flags &= ~(PCONN_ANSWER_IN_DATA_CHANNEL | PCONN_ANSWER_IS_APP_CHANNEL |
                           PCONN_ANSWER_IS_WEBRTC_CHAN | PCONN_ANSWER_IS_DTLS_SCTP );
  return 0;
}

static int pconn_sdp_media_ctl_fn(void *pc_, int op, void *arg) {
  struct pconn *pc = (struct pconn *) pc_;

  switch ( op ) {
  case SPS_MEDIA_SET_CONNECTION:
    return 0;
  case SPS_MEDIA_SET_TITLE:
    fprintf(stderr, "Set media title %s\n", (char *) arg);
    return 0;
  case SPS_MEDIA_SET_TYPE:
    if ( strcmp(arg, "application") != 0 )
      fprintf(stderr, "Expected 'application' as media stream, got %s\n", (char *)arg);
    else
      pc->pc_answer_flags |= PCONN_ANSWER_IS_APP_CHANNEL;
    return 0;
  case SPS_MEDIA_SET_PROTOCOL:
    if ( strcmp(arg, "DTLS/SCTP") != 0 )
      fprintf(stderr, "Expected 'DTLS/SCTP' as media protocol, got %s\n", (char *)arg);
    else
      pc->pc_answer_flags |= PCONN_ANSWER_IS_DTLS_SCTP;
    return 0;
  case SPS_MEDIA_SET_FORMAT:
    if ( strcmp(arg, "webrtc-datachannel") != 0 ) {
      int port;
      if ( parse_decimal(&port, arg, strlen(arg)) < 0 ) {
        fprintf(stderr, "Expected 'webrtc-datachannel' or port as format, got %s\n", (char *)arg);
        return -1;
      } else {
        pc->pc_answer_sctp = port;
        pc->pc_answer_flags |= PCONN_ANSWER_NEEDS_SCTPMAP;
      }
    } else
      pc->pc_answer_flags |= PCONN_ANSWER_IS_WEBRTC_CHAN;
    return 0;
  case SPS_MEDIA_SET_PORTS:
    fprintf(stderr, "Set media ports %d %d\n", ((uint16_t *) arg)[0], ((uint16_t *)arg)[1]);
    return 0;
  default:
    fprintf(stderr, "sdp_media_ctl_fn: %p %d %p\n", pc, op, arg);
    return -2;
  }
}

#define DIGEST_IS(dgt)                                                  \
  ((vle - vls) > strlen(dgt) &&                                         \
   (memcmp(vls, dgt, strlen(dgt)) == 0 ? (fingerprint = vls + strlen(dgt), 1) : 0))

static int pconn_parse_remote_fingerprint(struct pconn *pc, const char *vls, const char *vle) {
  const char *fingerprint, *cur;
  int i;
  const EVP_MD *md = NULL;
  if ( DIGEST_IS("sha-256 ") )
    md = EVP_sha256();

  if ( !md ) {
    fprintf(stderr, "pconn_parse_remote_fingerprint: unknown digest\n");
    return -1;
  }

  if ( EVP_MD_size(md) > sizeof(pc->pc_remote_cert_fingerprint) ) {
    fprintf(stderr, "pconn_parse_remote_fingerprint: not enough space\n");
    return -1;
  }

  for ( i = 0, cur = fingerprint; i < EVP_MD_size(md); ++i ) {
    unsigned char val;
    int dval;

    if ( i > 0 ) {
      if ( *cur != ':' ) {
        fprintf(stderr, "pconn_parse_remote_fingerprint: expected colon\n");
        return -1;
      } else
        cur++;
    }

    dval = hex_value(*cur);
    if ( dval < 0 ) {
      fprintf(stderr, "pconn_parse_remote_fingerprint: expected hex digit\n");
      return -1;
    }

    val = dval << 4;
    cur ++;

    dval = hex_value(*cur);
    if ( dval < 0 ) {
      fprintf(stderr, "pconn_parse_remote_fingerprint: expected hex digit\n");
      return -1;
    }
    val |= dval;
    cur++;

    pc->pc_remote_cert_fingerprint[i] = val;
  }

  pc->pc_remote_cert_fingerprint_digest = md;
  pc->pc_answer_flags |= PCONN_ANSWER_HAS_FINGERPRINT;
  return 0;
}

#define ATTR_IS(a) (strncmp(nms, a, (int)(nme - nms)) == 0)
#define VALUE_IS(a) (strncmp(vls, a, (int)(vle - vls)) == 0)
static int pconn_sdp_attr_fn(void *pc_, const char *nms, const char *nme,
                             const char *vls, const char *vle) {
  int err;
  struct pconn *pc = (struct pconn *) pc_;

  if ( (pc->pc_answer_flags & PCONN_ANSWER_IN_MEDIA_STREAM) == 0 ) {
    if ( ATTR_IS("fingerprint") && vls && vle && vls != vle ) {
      if ( pconn_parse_remote_fingerprint(pc, vls, vle) < 0 ) {
        fprintf(stderr, "could not parse fingerprint\n");
        return -1;
      }
    } else {
      fprintf(stderr, "Skipping session attribute %.*s\n",
              (int) (nme - nms), nms);
    }
  } else if ( (pc->pc_answer_flags & PCONN_ANSWER_DAT_CHAN_CREATD) &&
              (pc->pc_answer_flags & PCONN_ANSWER_IN_DATA_CHANNEL) == 0 ) {
    fprintf(stderr, "Skipping attribute %.*s because we've already processed the data channel\n",
            (int) (nme - nms), nms);
    return 0;
  } else if ( (pc->pc_answer_flags & PCONN_ANSWER_IS_APP_CHANNEL) == 0 ||
              (pc->pc_answer_flags & (PCONN_ANSWER_IS_WEBRTC_CHAN | PCONN_ANSWER_NEEDS_SCTPMAP)) == 0 ||
              (pc->pc_answer_flags & PCONN_ANSWER_IS_DTLS_SCTP) == 0 ) {
    fprintf(stderr, "Skipping attribute %.*s because this is not an application, WebRTC channel, or DTLS/SCTP channel\n",
            (int) (nme - nms), nms);
    return 0;
  } else {
    if ( ATTR_IS("ice-options") && vls && vle ) {
      if ( VALUE_IS("trickle") ) {
        pc->pc_answer_flags |= PCONN_ANSWER_ICE_TRICKLE;
      } else
        fprintf(stderr, "Unknown ice-options: %.*s\n", (int) (vle - vls), vls);
    } else if ( ATTR_IS("mid") && vls && vle ) {
      if ( VALUE_IS(PCONN_DATACHANNEL_MID) ) {
        pc->pc_answer_flags |= PCONN_ANSWER_IN_DATA_CHANNEL | PCONN_ANSWER_DAT_CHAN_CREATD;
      } else
        pc->pc_answer_flags &= ~PCONN_ANSWER_IN_DATA_CHANNEL;
    } else if ( ATTR_IS("ice-ufrag") && vls && vle ) {
      if ( (vle - vls) >= sizeof(pc->pc_remote_ufrag) ) {
        fprintf(stderr, "pconn_sdp_attr_fn: user fragment is too long (%"PRIuPTR")\n", vle - vls);
        return -1;
      } else {
        pc->pc_answer_flags |= PCONN_ANSWER_HAS_UFRAG;
        strncpy_fixed(pc->pc_remote_ufrag, sizeof(pc->pc_remote_ufrag),
                      vls, (int) (vle - vls));
      }
    } else if ( ATTR_IS("ice-pwd") && vls && vle ) {
      if ( (vle - vls) >= sizeof(pc->pc_remote_pwd) ) {
        fprintf(stderr, "pconn_sdp_attr_fn: password is too long (%"PRIuPTR")\n", vle - vls);
        return -1;
      } else {
        pc->pc_answer_flags |= PCONN_ANSWER_HAS_PASSWORD;
        strncpy_fixed(pc->pc_remote_pwd, sizeof(pc->pc_remote_pwd),
                      vls, (int) (vle - vls));
      }
    } else if ( ATTR_IS("setup") && vls && vle ) {
      if ( VALUE_IS("active") ) {
        pc->pc_answer_flags |= PCONN_ANSWER_IS_ACTIVE;
      } else if ( VALUE_IS("passive") ) {
        pc->pc_answer_flags |= PCONN_ANSWER_IS_PASSIVE;
      } else if ( VALUE_IS("actpass") ) {
        fprintf(stderr, "pconn_sdp_attr_fn: warning: actpass setup requested");
        pc->pc_answer_flags |= PCONN_ANSWER_IS_ACTIVE | PCONN_ANSWER_IS_PASSIVE;
      } else {
        fprintf(stderr, "pconn_sdp_attr_fn: unknown setup value: %.*s\n", (int) (vle - vls), vls);
        return -1;
      }
    } else if ( ATTR_IS("sctpmap") && vls && vle ) {
      char *porte = memchr(vls, ' ', vle - vls);

      if ( porte || (porte + 1) >= vle ) {
        int port;
        char *fmts = porte + 1;
        char *fmte = memchr(fmts, ' ', vle - fmts);
        if ( fmte ) {
          if ( parse_decimal(&port, vls, porte - vls) < 0 ) {
            fprintf(stderr, "Invalid port in sctpmap\n");
          } else {
            if ( strncmp(fmts, "webrtc-datachannel", fmte - fmts) == 0 ) {
              if ( pc->pc_answer_sctp == 0 )
                pc->pc_answer_sctp = port;
              else if ( pc->pc_answer_sctp == port &&
                        pc->pc_answer_flags & PCONN_ANSWER_NEEDS_SCTPMAP ) {
                pc->pc_answer_flags |= PCONN_ANSWER_IS_WEBRTC_CHAN;
              }
            } else
              fprintf(stderr, "pconn_sdp_attr_fn: sctpmap does not specify datachannel\n");
          }
        } else
          fprintf(stderr, "pconn_sdp_attr_fn: no format in sctpmap\n");
      } else
        fprintf(stderr, "pconn_sdp_attr_fn: no format in sctpmap\n");
    } else if ( ATTR_IS("sctp-port") && vls && vle ) {
      int port = 0;

      if ( vls == vle ) {
        fprintf(stderr, "sctp-port did not contain any data\n");
        return -1;
      }

      if ( parse_decimal(&port, vls, vle - vls) != (vle - vls) ){
        fprintf(stderr, "sctp-port attribute not a valid decimal\n");
        return -1;
      }

      pc->pc_answer_sctp = port;
    } else if ( ATTR_IS("candidate") && vls && vle && vls != vle ) {
      struct icecand cand;

      cand.ic_candsrc_ix = -1;

      fprintf(stderr, "attempting to parse ice candidate: %.*s\n", (int) (vle-vls), vls);
      err = icecand_parse(&cand, vls, vle);
      if ( err < 0 ) {
        fprintf(stderr, "could not parse ice candidate: %.*s\n",
                (int) (vle - vls), vls);
        return -1;
      }

      err = pconn_add_ice_candidate(pc, PCONN_REMOTE_CANDIDATE, &cand);
      if ( err < 0 ) {
        fprintf(stderr, "could not addd ice candidate\n");
        return -1;
      }

    } else if ( ATTR_IS("fingerprint") && vls && vle && vls != vle ) {
      if ( pconn_parse_remote_fingerprint(pc, vls, vle) < 0 ) {
        fprintf(stderr, "could not parse fingerprint\n");
        return -1;
      }
    } else {
      fprintf(stderr, "Unknown attribute: %.*s = %.*s\n", (int) (nme - nms), nms,
              (int) (vle - vls), vls);
    }
  }

  return 0;
}

static int pconn_ensure_dtls(struct pconn *pc) {
  BIO *dg_out = NULL, *dg_in = NULL;
  struct icecandpair *pair;
  struct icecand *local, *remote;
  struct candsrc *local_src;

  if ( pc->pc_dtls ) return 0;

  if ( pc->pc_active_candidate_pair < 0 ) {
    fprintf(stderr, "Cannot create DTLS context, because there is no active candidate pair\n");
    return -1;
  }

  pair = pc->pc_candidate_pairs_sorted[pc->pc_active_candidate_pair];
  if ( !pair || pair->icp_local_ix >= pc->pc_local_ice_candidates_count ||
       pair->icp_remote_ix >= pc->pc_remote_ice_candidates_count ) return -1;

  local = &pc->pc_local_ice_candidates[pair->icp_local_ix];
  if ( local->ic_candsrc_ix < 0 || local->ic_candsrc_ix >= pc->pc_candidate_sources_count ) return -1;

  remote = &pc->pc_remote_ice_candidates[pair->icp_remote_ix];

  local_src = &pc->pc_candidate_sources[local->ic_candsrc_ix];

  pc->pc_dtls = SSL_new(pc->pc_appstate->as_dtls_ctx);
  if ( !pc->pc_dtls ) {
    fprintf(stderr, "pconn_ensure_dtls: no more memory\n");
    return -1;
  }

  dg_out = BIO_new_dgram(local_src->cs_socket, BIO_NOCLOSE);
  if ( !dg_out ) {
    fprintf(stderr, "pconn_ensure_dtls: could not create datagram BIO\n");
    goto error;
  }

  fprintf(stderr, "Connecting to dtls on index %d ", pconn_cs_idx(local_src->cs_pconn, local_src));
  dump_address(stderr, &remote->ic_addr.ksa, sizeof(remote->ic_addr));
  if ( !BIO_ctrl(dg_out, BIO_CTRL_DGRAM_SET_PEER, 0, &remote->ic_addr.ksa) ) {
    BIO_free(dg_out);
    fprintf(stderr, "pconn_ensure_dtls: could not set BIO_dgram peer\n");
    goto error;
  }

  dg_in = BIO_new_static(BIO_STATIC_READ, &pc->pc_static_pkt_bio);
  if ( !dg_in ) {
    BIO_free(dg_out);
    fprintf(stderr, "pconn_ensure_dtls: could not create static BIO\n");
    goto error;
  }

  SSL_set_bio(pc->pc_dtls, dg_in, dg_out);

  if ( pc->pc_answer_flags & PCONN_ANSWER_IS_ACTIVE )
    SSL_set_accept_state(pc->pc_dtls);
  else
    SSL_set_connect_state(pc->pc_dtls);

  //  SSL_set_mode(pc->pc_dtls, SSL_MODE_AUTO_RETRY);

  if ( !SSL_set_pconn(pc->pc_dtls, pc) ) {
    fprintf(stderr, "pconn_ensure_dtls: could not SSL pconn\n");
    goto error;
  }

  fprintf(stderr, "pconn_ensure_dtls: got dtls %p\n", pc->pc_dtls);
  return 0;

 error:
  SSL_free(pc->pc_dtls);
  pc->pc_dtls = NULL;
  return -1;
}

static void pconn_dtls_handshake(struct pconn *pc) {
  int err;
  struct icecandpair *active;
  struct icecand *local;
  struct candsrc *src;
  BIO_ADDR *addr;

  assert(pc->pc_dtls);

  if ( pc->pc_active_candidate_pair < 0 || pc->pc_active_candidate_pair >= pc->pc_candidate_pairs_count )
    return;
  active = pc->pc_candidate_pairs_sorted[pc->pc_active_candidate_pair];

  if ( active->icp_local_ix >= pc->pc_local_ice_candidates_count )
    return;
  local = &pc->pc_local_ice_candidates[active->icp_local_ix];

  if ( local->ic_candsrc_ix < 0 || local->ic_candsrc_ix >= pc->pc_candidate_sources_count )
    return;
  src = &pc->pc_candidate_sources[local->ic_candsrc_ix];

  if ( pc->pc_state == PCONN_STATE_DTLS_STARTING ) {
    if ( pc->pc_answer_flags & PCONN_ANSWER_IS_PASSIVE )
      pc->pc_state = PCONN_STATE_DTLS_CONNECTING;
    else
      pc->pc_state = PCONN_STATE_DTLS_LISTENING;
  }

  pc->pc_dtls_needs_write = pc->pc_dtls_needs_read = 0;

  switch ( pc->pc_state ) {
  case PCONN_STATE_DTLS_LISTENING:
    addr = BIO_ADDR_new();
    if ( !addr ) {
      fprintf(stderr, "Could not allocate BIO_ADDR\n");
      return;
    }

    fprintf(stderr, "Running DTLSv1_listen, SSL_accept\n");

    errno = 0;
    BIO_ADDR_clear(addr);
    err = DTLSv1_listen(pc->pc_dtls, addr);
    if ( err <= 0 ) {
      err = SSL_get_error(pc->pc_dtls, err);
      switch ( err ) {
      case SSL_ERROR_WANT_READ:
        pc->pc_dtls_needs_read = 1;
        fprintf(stderr, "DTLSv1_listen wants read\n");
        BIO_ADDR_free(addr);
        return;
      case SSL_ERROR_WANT_WRITE:
        pc->pc_dtls_needs_write = 1;
        fprintf(stderr, "DTLSv1_listen wants write\n");
        CANDSRC_SUBSCRIBE_WRITE(src);
        BIO_ADDR_free(addr);
        return;
      default:
        perror("dtlsv1_listen");
        fprintf(stderr, "Error running DTLSv1_listen: %d\n", err);
        ERR_print_errors_fp(stderr);
        BIO_ADDR_free(addr);
        return;
      }
    } else {
      BIO_ADDR_free(addr);
      fprintf(stderr, "DTLSv1_listen returns success\n");
      pc->pc_state = PCONN_STATE_DTLS_ACCEPTING;
    }

  case PCONN_STATE_DTLS_ACCEPTING:
    err = SSL_accept(pc->pc_dtls);
    if ( err <= 0 ) {
      err = SSL_get_error(pc->pc_dtls, err);
      switch ( err ) {
      case SSL_ERROR_WANT_READ:
        pc->pc_dtls_needs_read = 1;
        fprintf(stderr, "SSL_acccept wants read\n");
        return;
      case SSL_ERROR_WANT_WRITE:
        pc->pc_dtls_needs_write = 1;
        fprintf(stderr, "SSL_accept wants write\n");
        CANDSRC_SUBSCRIBE_WRITE(src);
        return;
      default:
        fprintf(stderr, "Error running SSL_accept:\n");
        ERR_print_errors_fp(stderr);
        return;
      }
    } else {
      fprintf(stderr, "SSL_accept returns success\n");
      pc->pc_state = PCONN_STATE_ESTABLISHED;
    }

    pconn_on_established(pc);

    return;

  case PCONN_STATE_DTLS_CONNECTING:
    fprintf(stderr, "Running SSL_connect\n");
    err = SSL_connect(pc->pc_dtls);
    if ( err <= 0 ) {
      err = SSL_get_error(pc->pc_dtls, err);
      switch ( err ) {
      case SSL_ERROR_WANT_READ:
        fprintf(stderr, "SSL_connect wants read\n");
        return;
      case SSL_ERROR_WANT_WRITE:
        fprintf(stderr, "SSL_connect wants write\n");
        CANDSRC_SUBSCRIBE_WRITE(src);
        return;
      default:
        fprintf(stderr, "Error running SSL_connect:\n");
        ERR_print_errors_fp(stderr);
        return;
      };
    } else {
      fprintf(stderr, "Successfully ran SSL_connect\n");
      pc->pc_state = PCONN_STATE_ESTABLISHED;
    }

    pconn_on_established(pc);
    return;

  default:
    abort();
  }
}

static void pconn_on_established(struct pconn *pc) {
  int err;

  pconn_reset_connectivity_check_timeout(pc);

  switch ( pc->pc_type ) {
  case PCONN_TYPE_WEBRTC:
    fprintf(stderr, "pconn_on_established: launching webrtc proxy in persona on port %d\n", pc->pc_answer_sctp);

    if ( !pc->pc_persona ) {
      fprintf(stderr, "pconn_on_established: no persona!!\n");
      return;
    }

    if ( pc->pc_answer_sctp == 0 ) {
      fprintf(stderr, "pconn_on_established: no sctp-port in answer\n");
      return;
    }

    err = container_ensure_running(&pc->pc_container, &pc->pc_appstate->as_eventloop);
    if ( err < 0 ) {
      fprintf(stderr, "pconn_on_established: could not start container\n");
      return;
    } else if ( err == 0 ) {
      // We didn't start this, so release it
      container_release_running(&pc->pc_container, &pc->pc_appstate->as_eventloop);
    } else {
      // We started the container, so keep a reference
      PCONN_REF(pc);

      // Also add this to the bridge
      pc->pc_sctp_capture.se_source.sin_addr.s_addr = pc->pc_container.c_ip.s_addr;
      pc->pc_sctp_capture.se_source.sin_port = htons(pc->pc_sctp_port);

      fprintf(stderr, "Started webrtc proxy\n");
      if ( bridge_register_sctp(&pc->pc_appstate->as_bridge, &pc->pc_sctp_capture) < 0 ) {
        fprintf(stderr, "pconn_on_established: could not register with bridge\n");
        // TODO kill the webrtc-proxy process
        return;
      } else
        // We must keep this alive while the bridge is delivering events...
        // TODO undo this reference
        PCONN_WREF(pc);

      // Open up all bridge ports for registered apps
      pconn_enable_traffic_deferred(pc);
    }
    break;

  default:
    fprintf(stderr, "pconn_on_established: unknown type %d\n", pc->pc_type);
  }
}

static void pconn_on_sctp_packet(struct sctpentry *se, const void *buf, size_t sz) {
  struct pconn *pc = STRUCT_FROM_BASE(struct pconn, pc_sctp_capture, se);

  if ( sz > PCONN_MAX_PACKET_SIZE ) {
    fprintf(stderr, "pconn_on_sctp_packet: packet is too large\n");
    return;
  }

  //fprintf(stderr, "pconn_on_sctp_packet: receive sctp packet\n");

  if ( pthread_mutex_lock(&pc->pc_mutex) == 0 ) {
    size_t aligned_sz = ((sz + 3) / 4) * 4;
    size_t cur_write_head = pc->pc_outgoing_offs + pc->pc_outgoing_size;
    struct icecandpair *active;
    struct icecand *local_cand;
    struct candsrc *candsrc;
    cur_write_head %= sizeof(pc->pc_outgoing_pkt);

    //    fprintf(stderr, "pconn: receive buffer %p %lu\n", buf, sz);

    if ( pc->pc_active_candidate_pair < 0 ||
         pc->pc_active_candidate_pair >= pc->pc_candidate_pairs_count ) {
      fprintf(stderr, "pconn_on_sctp_packet: invalid candidate pair\n");
      goto done;
    }
    active = pc->pc_candidate_pairs_sorted[pc->pc_active_candidate_pair];
    if ( !active ) {
      fprintf(stderr, "pconn_on_sctp_packet: null in candidate pair list\n");
      goto done;
    }

    if ( active->icp_local_ix >= pc->pc_local_ice_candidates_count ) {
      fprintf(stderr, "pconn_on_sctp_packet: invalid local ice candidate\n");
      goto done;
    }
    local_cand = &pc->pc_local_ice_candidates[active->icp_local_ix];

    if ( local_cand->ic_candsrc_ix < 0 ||
         local_cand->ic_candsrc_ix >= pc->pc_candidate_sources_count ) {
      fprintf(stderr, "pconn_on_sctp_packet: invalid candidate source index\n");
      goto done;
    }
    candsrc = &pc->pc_candidate_sources[local_cand->ic_candsrc_ix];
    //    fprintf(stderr, "Writing on cand pair %d\n", pc->pc_active_candidate_pair);
    //fprintf(stderr, "Requesting write for cs ix %d\n", local_cand->ic_candsrc_ix);

    aligned_sz += 4;

    if ( (pc->pc_outgoing_size + aligned_sz) <= sizeof(pc->pc_outgoing_pkt) ) {
      uint32_t size4 = sz;
      size_t bytes_available = sizeof(pc->pc_outgoing_pkt) - cur_write_head, bytes_written = 0;

      assert(bytes_available >= 4);
      memcpy(pc->pc_outgoing_pkt + cur_write_head, &size4, 4);

      if ( bytes_available < aligned_sz ) {
        bytes_available -= 4;
        if ( bytes_available > 0 ) {
          memcpy(pc->pc_outgoing_pkt + cur_write_head + 4, buf, bytes_available);
          bytes_written += bytes_available;
        }
        cur_write_head = 0;
      } else
        cur_write_head += 4;

      //fprintf(stderr, "pconn_on_sctp_packet: write at %lu\n", cur_write_head);
      memcpy(pc->pc_outgoing_pkt + cur_write_head, buf + bytes_written, aligned_sz - 4 - bytes_written);
      pc->pc_outgoing_size += aligned_sz;

      //fprintf(stderr, "pconn_on_sctp_packet: asking for write\n");
      CANDSRC_SUBSCRIBE_WRITE(candsrc);
    } else
      fprintf(stderr, "pconn_on_sctp_packet: dropping packet\n"); // TODO drop first packet
  done:
    pthread_mutex_unlock(&pc->pc_mutex);
  } else
    fprintf(stderr, "pconn_on_sctp_packet: can't lock mutex\n");
}

static void pconn_teardown_established(struct pconn *pc) {
  if ( pc->pc_state == PCONN_STATE_ESTABLISHED ) {
    pc->pc_state = PCONN_STATE_DISCONNECTED;

    SHARED_DEBUG(&pc->pc_shared, "on pconn teardown");

    if ( bridge_unregister_sctp(&pc->pc_appstate->as_bridge, &pc->pc_sctp_capture) < 0 ) {
      fprintf(stderr, "pconn_teardown_established: failed to unregister sctp capture\n");
      return;
    }

    PCONN_WUNREF(pc); // For bridge capture
    SHARED_DEBUG(&pc->pc_shared, "after bridge unregister");

    assert( container_release_running(&pc->pc_container, &pc->pc_appstate->as_eventloop) );

    pconn_finish(pc);
  }
}

#define MAX_PORT_SZ 5
static int pconn_container_fn(struct container *c, int op, void *argp, ssize_t argl) {
  struct pconn *pc = STRUCT_FROM_BASE(struct pconn, pc_container, c);
  struct brpermrequest *perm;
  const char **cp;
  char *port_str, *hostname;
  int err;

  struct arpdesc *desc;

  switch ( op ) {
  case CONTAINER_CTL_DESCRIBE:
    desc = argp;
    desc->ad_container_type = ARP_DESC_PERSONA;
    memcpy(desc->ad_persona.ad_persona_id, pc->pc_persona->p_persona_id,
           sizeof(desc->ad_persona.ad_persona_id));
    desc->ad_persona.ad_pconn = pc;
    PCONN_REF(pc);
    return 0;

  case CONTAINER_CTL_CHECK_PERMISSION:
    perm = argp;
    if ( perm->bpr_perm.bp_type == BR_PERM_APPLICATION ) {
      PERSONA_REF(pc->pc_persona);
      perm->bpr_persona = pc->pc_persona;
      return 0;
    }
    return 0;

  case CONTAINER_CTL_GET_INIT_PATH:
    cp = argp;
    *cp = pc->pc_appstate->as_webrtc_proxy_path;
    return 0;

  case CONTAINER_CTL_GET_ARGS:
    if ( argl < 2 ) {
      fprintf(stderr, "pconn_container_fn: not enough space for args\n");
      return -1;
    }

    cp = argp;
    cp[0] = port_str = malloc(MAX_PORT_SZ + 1);
    if ( !cp[0] ) return -1;
    snprintf(port_str, MAX_PORT_SZ + 1, "%d", pc->pc_answer_sctp);

    cp[1] = "TODO capability";
    return 2;

  case CONTAINER_CTL_GET_HOSTNAME:
    cp = argp;
    err = snprintf(NULL, 0, "pconn-%"PRIu64, pc->pc_conn_id);

    *cp = hostname = malloc(err + 1);
    snprintf(hostname, err + 1, "pconn-%"PRIu64, pc->pc_conn_id);

    return 0;

  case CONTAINER_CTL_RELEASE_HOSTNAME:
    free((char *)argp);
    return 0;

  case CONTAINER_CTL_RELEASE_ARG:
    if ( argl == 0 )
      free((char *) argp);
    return 0;

  case CONTAINER_CTL_RELEASE_INIT_PATH:
    return 0;

  case CONTAINER_CTL_ON_SHUTDOWN:
    PCONN_UNREF(pc);
    return 0;

  default:
    fprintf(stderr, "pconn_container_fn: unrecognized op %d\n", op);
    return -2;
  }
}

int pconn_add_token(struct pconn *pc, struct token *tok) {
  if ( pthread_mutex_lock(&pc->pc_mutex) == 0 ) {
    int ret = pconn_add_token_unlocked(pc, tok);
    pthread_mutex_unlock(&pc->pc_mutex);
    return ret;
  } else
    return -1;
}

int pconn_add_token_unlocked(struct pconn *pc, struct token *tok) {
  struct pconntoken *pct;
  HASH_FIND(pct_hh, pc->pc_tokens, tok->tok_token_id, sizeof(tok->tok_token_id), pct);

  if ( !pct ) {
    pct = malloc(sizeof(*pct));
    if ( !pct ) {
      return -1;
    }

    TOKEN_REF(tok);
    pct->pct_token = tok;
    pct->pct_started = 0;
    HASH_ADD_KEYPTR(pct_hh, pc->pc_tokens, tok->tok_token_id, sizeof(tok->tok_token_id), pct);

    // Queue the start event
    PCONN_WREF(pc);
    if ( !eventloop_queue(&pc->pc_appstate->as_eventloop,
                          &pc->pc_new_token_evt) ) {
      PCONN_WUNREF(pc);
    }
  }
  return 0;
}

static int pconn_launch_app(struct pconn *pc, const char *app_uri, struct pconnapp **pca) {
  struct pconnapp *existing;

  *pca = NULL;

  HASH_FIND(pca_hh, pc->pc_apps, app_uri, strlen(app_uri), existing);
  if ( !existing ) {
    struct app *a = appstate_get_app_by_url(pc->pc_appstate, app_uri);
    if ( !a ) {
      fprintf(stderr, "pconn_launch_app: could not find app %s: skipping\n",
              app_uri);
      return -1;
    } else {
      existing = malloc(sizeof(*existing));
      if ( !existing ) {
        APPLICATION_UNREF(a);
        fprintf(stderr, "pconn_launch_app: could not allocate new pconnapp\n");
        return -1;
      }

      existing->pca_tun = NULL;
      existing->pca_app = launch_app_instance(pc->pc_appstate, pc->pc_persona, a);
      APPLICATION_UNREF(a);
      if ( !existing->pca_app ) {
        free(existing);
        fprintf(stderr, "pconn_launch_app: could not launch application instance for %s\n",
                app_uri);
        return -1;
      }

      HASH_ADD_KEYPTR(pca_hh, pc->pc_apps,
                      existing->pca_app->inst_app->app_domain,
                      strlen(existing->pca_app->inst_app->app_domain),
                      existing);

      *pca = existing;
      return 1;
    }
  } else {
    *pca = existing;
    return 0;
  }
}

// pc_mutex should be locked
static int pconnapp_enable_traffic(struct pconn *pc, struct pconnapp *pca) {
  if ( pca->pca_tun ) return 1;
  else {
    if ( container_is_running(&pc->pc_container) ) {
      struct brtunnel *tun =
        bridge_create_tunnel(&pc->pc_appstate->as_bridge,
                             pc->pc_container.c_bridge_port,
                             pca->pca_app->inst_container.c_bridge_port);
      if ( !tun ) return -1;

      fprintf(stderr, "pconnapp: create tunnel %d -> %d\n",
              pc->pc_container.c_bridge_port,
              pca->pca_app->inst_container.c_bridge_port);

      pca->pca_tun = tun;
      return 1;
    } else
      return 0;
  }
}

static void pconn_on_new_tokens(struct pconn *pc) {
  struct pconntoken *tok, *tmp;
  int i;

  HASH_ITER(pct_hh, pc->pc_tokens, tok, tmp) {
    if ( !tok->pct_started ) {
      tok->pct_started = 1;

      // Launch the application instances
      for ( i = 0; i < tok->pct_token->tok_app_count; ++i ) {
        struct pconnapp *pca;
        int err = pconn_launch_app(pc, tok->pct_token->tok_apps[i], &pca);
        if ( err < 0 ) {
          fprintf(stderr, "pconn_on_new_tokens: could not launch app %s\n", tok->pct_token->tok_apps[i]);
        } else if ( err > 0 ) {
          fprintf(stderr, "pconn_on_new_tokens: Adding app access to %s from port %d\n",
                  tok->pct_token->tok_apps[i], pc->pc_container.c_bridge_port);

          err = pconnapp_enable_traffic(pc, pca);
          if ( err < 0 ) {
            fprintf(stderr, "pconn_on_new_tokens: pconnapp_enable_traffic failed\n");
          } else if ( err == 0 ) {
            fprintf(stderr, "pconn_on_new_tokens: pconnapp_enable_traffic: container not running yet\n");
          }
        }
      }
    }
  }
}

static void pconn_enable_traffic_deferred(struct pconn *pc) {
  struct pconnapp *app, *tmp;

  HASH_ITER(pca_hh, pc->pc_apps, app, tmp) {
    int err = pconnapp_enable_traffic(pc, app);
    if ( err < 0 ) {
      fprintf(stderr, "pconn_enable_traffic_deferred: pconn_app_enable_traffic failed\n");
    } else if ( err == 0 ) {
      fprintf(stderr, "pconn_enable_traffic_deferred: container not running!\n");
      abort();
    }
  }
}
