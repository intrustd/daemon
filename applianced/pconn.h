#ifndef __appliance_pconn_H__
#define __appliance_pconn_H__

#include <uthash.h>
#include <stdint.h>

#include "event.h"
#include "stun.h"
#include "persona.h"

#define PCONN_TIMEOUT (2 * 60 * 1000)

// 200 milliseconds max default jitter
#define PCONN_CANDSRC_JITTER 200
#define PCONN_MAX_AUTH_ATTEMPTS 3
#define PCONN_MAX_MESSAGE_SIZE (16 * 1024)
#define PCONN_MAX_SCTP_STREAMS 1024
#define PCONN_OUR_UFRAG_SIZE 4
#define PCONN_OUR_PASSWORD_SIZE 24

struct flock;
struct appstate;
struct candsrc;

struct pconn {
  struct shared pc_shared;

  uint64_t pc_conn_id;

  struct appstate *pc_appstate;
  struct flock *pc_flock;

  pthread_mutex_t pc_mutex;

  struct stuntxid pc_tx_id;
  uint16_t pc_last_req;

  // Datagram socket used to send STUN requests and receive responses
  int pc_socket;
  struct fdsub pc_socket_sub;

  // An event that is triggered to start action on this PCONN (ICE
  // candidate collection and other delayed initialization)
  struct qdevtsub pc_start_evt;

  // Along with the channel, a pending connection has several STUN /
  // TURN servers. These are collected from the set of flocks in the
  // appstate
  struct candsrc *pc_candidate_sources;
  int pc_candidate_sources_count;

  int pc_state;
  int pc_ice_gathering_state;
  int pc_type;

  int pc_auth_attempts;
  int pc_offer_line;

  uint16_t pc_sctp_port; // The port that has been allocated in the persona proxy for our use
  char pc_our_ufrag[PCONN_OUR_UFRAG_SIZE];
  char pc_our_pwd[PCONN_OUR_PASSWORD_SIZE];

  // entry in f_pconns hash table
  UT_hash_handle pc_hh;

  struct timersub pc_timeout;

  struct personaset *pc_personaset;

  struct persona *pc_persona;

  // Entry in struct flock f_pconns_with_response
  DLIST(struct pconn) pc_pconns_with_response_dl;
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
// An ice candidate has been selected
#define PCONN_STATE_ESTABLISHED    0x6

#define PCONN_ICE_GATHERING_STATE_ERROR     (-1)
#define PCONN_ICE_GATHERING_STATE_NEW       1
#define PCONN_ICE_GATHERING_STATE_GATHERING 2
#define PCONN_ICE_GATHERING_STATE_COMPLETE  3

// There was an error establishing the connection
#define PCONN_STATE_ERROR             (-1)
#define PCONN_STATE_ERROR_AUTH_FAILED (-2)

#define PCONN_IS_ERRORED(pc) ((pc)->pc_state <= PCONN_STATE_ERROR)
#define PCONN_CAN_AUTH(pc)                              \
  ((pc)->pc_state == PCONN_STATE_WAIT_FOR_LOGIN ||      \
   (pc)->pc_state == PCONN_STATE_ERROR_AUTH_FAILED)

struct pconn *pconn_alloc(uint64_t conn_id, struct flock *f, struct appstate *as, int type);
// Completes all services on this connection and requests the flock gets rid of it
void pconn_finish(struct pconn *pc);

void pconn_start_service(struct pconn *pc);
void pconn_set_request(struct pconn *pc, uint16_t req, const struct stuntxid *id);

int pconn_write_response(struct pconn *pc, char *buf, int buf_sz);

// flock mutex must be locked
void pconn_recv_startconn(struct pconn *pc, const char *persona_id,
                          const char *credential, size_t cred_sz);
void pconn_recv_sendoffer(struct pconn *pc, int line);

#endif
