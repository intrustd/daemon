#ifndef __appliance_pconn_H__
#define __appliance_pconn_H__

#include <uthash.h>
#include <stdint.h>

#include "event.h"
#include "stun.h"
#include "persona.h"
#include "sdp.h"
#include "util.h"

#define PCONN_TIMEOUT (2 * 60 * 1000)

// 200 milliseconds max default jitter
#define PCONN_CANDSRC_JITTER 200
#define PCONN_MAX_AUTH_ATTEMPTS 3
#define PCONN_MAX_MESSAGE_SIZE (8 * 1024)
#define PCONN_MAX_PACKET_SIZE (2 * 1024)
#define PCONN_OUTGOING_QUEUE_SIZE (64 * 1024)
#define PCONN_MAX_SCTP_STREAMS 1024
#define PCONN_OUR_UFRAG_SIZE 4
#define PCONN_OUR_PASSWORD_SIZE 24
#define PCONN_MAX_UFRAG_SIZE 32
#define PCONN_MAX_PASSWORD_SIZE 128
#define PCONN_MAX_CANDIDATES 32 // Accept 32 candidates each

// Send connectivity checks every 100 milliseconds
#define PCONN_CONNECTIVITY_CHECK_INTERVAL 100
// After we've connected, send a check every 500 milliseconds
#define PCONN_CONNECTIVITY_CHECK_CONNECTED_INTERVAL 500

// If we don't receive an answer to our connectivity check after two minutes, fault
#define PCONN_CONNECTIVITY_CHECK_TIMEOUT (2 * 60 * 1000)

struct flock;
struct appstate;
struct candsrc;
struct token;

#define ICE_ROLE_CONTROLLING 1
#define ICE_ROLE_CONTROLLED  2

#define ICE_TYPE_HOST  1
#define ICE_TYPE_SRFLX 2
#define ICE_TYPE_PRFLX 3
#define ICE_TYPE_RELAY 4

#define ICE_FOUNDATION_LEN 10

struct pconn;
struct icecand {
  char ic_foundation[32];

  uint8_t ic_component;

  int ic_transport; // IPPROTO_UDP or IPPROTO_TCP
  int ic_type;
  uint32_t ic_priority;

  kite_sock_addr ic_addr;
  kite_sock_addr ic_raddr;

  // If a local candidate, the index into the candidate_source array that generated this candidate.
  //
  // Otherwise -1
  int ic_candsrc_ix;
};

#define ICECAND_CAN_PAIR(a, b)                                          \
  (((a)->ic_component == (b)->ic_component) &&                          \
   ((a)->ic_addr.ksa.sa_family == (b)->ic_addr.ksa.sa_family) &&        \
   (a)->ic_addr.ksa.sa_family != AF_UNSPEC)
uint64_t icecand_pair_priority(struct pconn *pc, struct icecand *local, struct icecand *remote);
int icecand_equivalent(struct icecand *a, struct icecand *b);

#define ICECANDPAIR_FLAG_NOMINATED   0x1 // We've performed a successful connectivity check
// #define ICECANDPAIR_FLAG_RECEIVED    0x2 // We've received a successful STUN ping
#define ICECANDPAIR_FLAG_ERROR       0x4 // Both nominated and received (or them together)

#define ICECANDPAIR_SUCCESS(icp)                                        \
  (((icp)->icp_flags & ICECANDPAIR_FLAG_NOMINATED) ==			\
   ICECANDPAIR_FLAG_NOMINATED)

struct icecandpair {
  unsigned int    icp_local_ix, icp_remote_ix;
  struct stuntxid icp_tx_id;
  UT_hash_handle  icp_hh;
  uint64_t        icp_priority;
  int             icp_flags;
};

struct pconntoken {
  UT_hash_handle pct_hh;
  struct token  *pct_token;
  int pct_started : 1;
};

struct pconnapp {
  UT_hash_handle pca_hh;
  struct appinstance *pca_app;
  struct brtunnel *pca_tun;
};

struct pconn {
  struct shared pc_shared;

  uint64_t pc_conn_id;

  struct appstate *pc_appstate;
  struct flock *pc_flock;

  pthread_mutex_t pc_mutex;

  struct stuntxid pc_tx_id;
  uint16_t pc_last_req;

  SSL *pc_dtls;
  int pc_dtls_needs_write : 1;
  int pc_dtls_needs_read : 1;
  int pc_is_logged_in : 1; // Whether or not this pconn was authenticated using username/password

  // An event that is triggered to start action on this PCONN (ICE
  // candidate collection and other delayed initialization)
  struct qdevtsub pc_start_evt;

  // An event that is triggered when there are one or more new tokens
  struct qdevtsub pc_new_token_evt;

  // Along with the channel, a pending connection has several STUN /
  // TURN servers. These are collected from the set of flocks in the
  // appstate
  struct candsrc *pc_candidate_sources;
  int pc_candidate_sources_count;

  struct icecand *pc_local_ice_candidates;
  int pc_local_ice_candidates_count;
  int pc_local_ice_candidates_array_size;

  struct icecand *pc_remote_ice_candidates;
  int pc_remote_ice_candidates_count;
  int pc_remote_ice_candidates_array_size;

  struct icecandpair **pc_candidate_pairs_sorted;
  int pc_candidate_pairs_count, pc_candidate_pair_pending_ix;
  int pc_active_candidate_pair;

  int pc_state;
  int pc_ice_gathering_state : 4;
  int pc_type : 4;

  int pc_auth_attempts : 2;
  int pc_ice_role : 2; // ICE_ROLE_CONTROLLING or ICE_ROLE_CONTROLLED
  int pc_offer_line;
  int pc_last_offer_line; // index of offer line of first candidate

  uint64_t pc_tie_breaker;

  int pc_answer_offset;
  struct sdpparsest pc_answer_parser;
  uint32_t pc_answer_flags;
  uint16_t pc_answer_sctp;

  uint16_t pc_sctp_port; // The port that has been allocated in the persona proxy for our use
  char pc_our_ufrag[PCONN_OUR_UFRAG_SIZE];
  char pc_our_pwd[PCONN_OUR_PASSWORD_SIZE];

  char pc_remote_ufrag[PCONN_MAX_UFRAG_SIZE];
  char pc_remote_pwd[PCONN_MAX_PASSWORD_SIZE];

  char pc_remote_cert_fingerprint[SHA256_DIGEST_LENGTH];
  const EVP_MD *pc_remote_cert_fingerprint_digest;

  // entry in f_pconns hash table
  UT_hash_handle pc_hh;

  struct timersub pc_timeout, pc_conn_check_timer, pc_conn_check_timeout_timer;

  struct personaset *pc_personaset;

  struct persona *pc_persona;

  // Entry in struct flock f_pconns_with_response
  DLIST(struct pconn) pc_pconns_with_response_dl;

  struct sctpentry pc_sctp_capture;

  struct BIO_static pc_static_pkt_bio;
  char pc_incoming_pkt[PCONN_MAX_PACKET_SIZE];

  size_t pc_outgoing_size, pc_outgoing_offs;
  char pc_outgoing_pkt[PCONN_OUTGOING_QUEUE_SIZE];

  struct pconntoken *pc_tokens;
  struct pconnapp *pc_apps;

  struct container pc_container;
};

#define PCONN_REF(pc) SHARED_REF(&(pc)->pc_shared)
#define PCONN_UNREF(pc) SHARED_UNREF(&(pc)->pc_shared)
#define PCONN_WREF(pc) SHARED_WREF(&(pc)->pc_shared)
#define PCONN_WUNREF(pc) SHARED_WUNREF(&(pc)->pc_shared)
#define PCONN_LOCK(pc) SHARED_LOCK(&(pc)->pc_shared)

// Establish a WebRTC connection
#define PCONN_TYPE_WEBRTC 0x1

// States

// There was an error collecting ice candidates
#define PCONN_STATE_ICE_GATHERING_ERROR (-1)
// Waiting for persona log-in request
#define PCONN_STATE_WAIT_FOR_LOGIN 0x1
// No offer has been sent, but a persona has been collected
#define PCONN_STATE_START_OFFER    0x2
// We are currently sending the offer
#define PCONN_STATE_SENDING_OFFER  0x3
// An offer was sent but no answer received
#define PCONN_STATE_OFFER_SENT     0x4
// An offer was sent and a valid answer received
#define PCONN_STATE_ANSWER_RECVD   0x5
// A candidate pair is active but we need to do the dtls handshake
#define PCONN_STATE_DTLS_STARTING   0x6
#define PCONN_STATE_DTLS_LISTENING  0x7
#define PCONN_STATE_DTLS_ACCEPTING  0x8
#define PCONN_STATE_DTLS_CONNECTING 0x9
// An ice candidate has been selected, and DTLS has completed
#define PCONN_STATE_ESTABLISHED    0xA

// pconn has been disconnect
#define PCONN_STATE_DISCONNECTED   0xB

#define PCONN_ICE_GATHERING_STATE_ERROR     (-1)
#define PCONN_ICE_GATHERING_STATE_NEW       1
#define PCONN_ICE_GATHERING_STATE_GATHERING 2
#define PCONN_ICE_GATHERING_STATE_COMPLETE  3

// There was an error establishing the connection
#define PCONN_STATE_ERROR             (-1)
#define PCONN_STATE_ERROR_AUTH_FAILED (-2)
#define PCONN_STATE_ERROR_BAD_ANSWER  (-3)

#define PCONN_ANSWER_HAS_UFRAG       0x0001
#define PCONN_ANSWER_HAS_PASSWORD    0x0002
#define PCONN_ANSWER_ICE_TRICKLE     0x0004
#define PCONN_ANSWER_HAS_FINGERPRINT 0x0008
#define PCONN_ANSWER_IS_ACTIVE       0x0010
#define PCONN_ANSWER_IS_PASSIVE      0x0020
#define PCONN_ANSWER_HAS_SCTP_PORT   0x0040
#define PCONN_ANSWER_IN_MEDIA_STREAM 0x0080
#define PCONN_ANSWER_DAT_CHAN_CREATD 0x0100
#define PCONN_ANSWER_IN_DATA_CHANNEL 0x0200
#define PCONN_ANSWER_IS_APP_CHANNEL  0x0400
#define PCONN_ANSWER_IS_WEBRTC_CHAN  0x0800
#define PCONN_ANSWER_IS_DTLS_SCTP    0x1000
#define PCONN_ANSWER_NEEDS_SCTPMAP   0x2000

#define PCONN_DATACHANNEL_MID "data"

#define PCONN_IS_ERRORED(pc) ((pc)->pc_state <= PCONN_STATE_ERROR)
#define PCONN_CAN_AUTH(pc)                              \
  ((pc)->pc_state == PCONN_STATE_WAIT_FOR_LOGIN ||      \
   (pc)->pc_state == PCONN_STATE_ERROR_AUTH_FAILED)

#define PCONN_READY_FOR_ICE_ANSWER_FLAGS (PCONN_ANSWER_HAS_UFRAG | PCONN_ANSWER_HAS_PASSWORD | PCONN_ANSWER_DAT_CHAN_CREATD)
#define PCONN_READY_FOR_ICE(pc)                                         \
  (((pc)->pc_answer_flags & PCONN_READY_FOR_ICE_ANSWER_FLAGS) ==        \
   PCONN_READY_FOR_ICE_ANSWER_FLAGS)

struct pconn *pconn_alloc(uint64_t conn_id, struct flock *f, struct appstate *as, int type);
// Completes all services on this connection and requests the flock gets rid of it
void pconn_finish(struct pconn *pc);

void pconn_start_service(struct pconn *pc);
void pconn_set_request(struct pconn *pc, uint16_t req, const struct stuntxid *id);

int pconn_write_response(struct pconn *pc, char *buf, int buf_sz);

// flock mutex must be locked
void pconn_recv_startconn(struct pconn *pc, const char *persona_id,
                          const char *credential, size_t cred_sz);
void pconn_recv_sendoffer(struct pconn *pc, int line, const char *answer, uint16_t answer_offs, size_t answer_sz);

int pconn_add_token(struct pconn *pc, struct token *tok);
int pconn_add_token_unlocked(struct pconn *pc, struct token *tok);

#endif
