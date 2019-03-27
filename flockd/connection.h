#ifndef __flock_connection_H__
#define __flock_connection_H__

#include <uthash.h>

#include "personas.h"
#include "client.h"
#include "event.h"
#include "util.h"
#include "stun.h"
#include "sdp.h"

// We give connections exactly 2 minutes to establish
#define CONNECTION_TIMEOUT (60000 * 2)
// Wait 200 milliseconds for the first reply from appliance
#define CONNECTION_APPLIANCE_TIMEOUT 2000
#define CONNECTION_ICE_COLLECTION_INTERVAL 500
#define MAX_CONNECTION_RETRY 7
#define MAX_CREDENTIAL_SZ 256
#define MAX_CONNECTION_ANSWER_SZ (16 * 1024)

struct connection;
struct appplianceinfo;
struct flockservice;

typedef int(*connectionfn)(struct connection *, int, void*);

// Called when the connection has timed out. Arg is null
#define CONNECTION_OP_TIMEOUT                 0x1
// Called when a new candidate becomes available from the appliance
#define CONNECTION_OP_APPLIANCE_CAND_RECEIVED 0x2
// Called when the connection is being freed and there are no more references
#define CONNECTION_OP_RELEASE                 0x3
// The startconn or sendoffer request was sent
#define CONNECTION_OP_APP_REQ_SENT            0x4
// Start the login process
#define CONNECTION_OP_START_LOGIN             0x5
// Called when only weak references exist and the connection will no longer be used
#define CONNECTION_OP_RELEASE_WEAK            0x6
// Called when there is an error. Arg is a pointer to an int containing CONNECTION_ERR_* constants
#define CONNECTION_OP_SIGNAL_ERROR            0x7
// Start the auth process
#define CONNECTION_OP_START_AUTH              0x8
// Start ICE
#define CONNECTION_OP_START_ICE               0x9
// Parameter is struct sdpln
#define CONNECTION_OP_SEND_OFFER_LINE         0xA
#define CONNECTION_OP_COMPLETE_OFFER          0xB
#define CONNECTION_OP_COMPLETE_ICE_CANDIDATES 0xC
#define CONNECTION_OP_COMPLETE                0xD
#define CONNECTION_OP_SEND_PERSONAS           0xE

// Personas were available, but there was an error fetching them
#define CONNECTION_ERR_COULD_NOT_SEND_PERSONAS 1
// The appliance returned an error when starting the connection
#define CONNECTION_ERR_NO_CONNECTION           2
// The appliance rejected our credentials
#define CONNECTION_ERR_INVALID_CREDENTIALS     3
// An internal flock server error
#define CONNECTION_ERR_SERVER                  4

struct sdpln {
  const char *sl_start, *sl_end;
};

// A particular initator for a connection
struct connection {
  struct shared   conn_shared;

  struct flockservice *conn_svc;
  struct eventloop    *conn_el;

  pthread_mutex_t conn_mutex;

  // A random non-zero 64-bit integer that uniquely identifies this connection
  uint64_t conn_id;
  uint8_t conn_format;

  connectionfn conn_control;

  // Entry in the global hash table of connections
  UT_hash_handle conn_hh;

  // A timer that is used to timeout this connection
  struct timersub conn_timeout;

  // Struct members for communication with appliance

  // The appliance we are trying to connect to
  struct applianceinfo *conn_appliance;

  struct personasfetcher *conn_personas;
  struct personaswriter   conn_personas_writer;
  struct qdevtsub         conn_personas_ready_evt;

  unsigned char conn_persona_id[SHA256_DIGEST_LENGTH];
  char conn_credential[MAX_CREDENTIAL_SZ];
   size_t conn_credential_sz;

  // The state of establishing the connection with the appliance
  int conn_ai_state;
  int conn_ai_offer_line;

  int conn_ai_appliance_ice_complete : 1;
  int conn_ai_client_ice_complete : 1;

  // The number of times we've tried to send this to the appliance
  int conn_ai_retries;

  // Hash entry in struct applianceinfo ai_connections
  UT_hash_handle conn_ai_hh;

  // A timer that rings whenever we have to retry sending the connect request to the device
  struct timersub conn_ai_retry_connect;

  struct fcspktwriter conn_outgoing_packet;
  struct stuntxid conn_start_tx_id;

  // Dynamically allocated buffer for storing the SDP answer
  struct buffer conn_answer_buffer;
  // The highest offset of the answer buffer that has been transferred to the appliance
  uint16_t conn_answer_offset;
};

#define CONN_REF(conn) SHARED_REF(&(conn)->conn_shared)
#define CONN_WREF(conn) SHARED_WREF(&(conn)->conn_shared)
#define CONN_WUNREF(conn) SHARED_WUNREF(&(conn)->conn_shared)
#define CONN_LOCK(conn) SHARED_LOCK(&(conn)->conn_shared)
#define CONN_UNREF(conn) SHARED_UNREF(&(conn)->conn_shared)
#define CONN_SAFE_LOCK(conn, d) SHARED_SAFE_LOCK(&(conn)->conn_shared, d)

// conn_ai_state_values

#define CONN_AI_STATE_COMPLETE         0
// The connection needs to be communicated to the device
#define CONN_AI_STATE_STARTING         1
// The connection has been communicated to the device, but we have not
// received confirmation yet. This state may lead to the previous
// state due to a timeout.
#define CONN_AI_STATE_WAITING_TO_START 2
// The connection has personas it is advertising to us
#define CONN_AI_STATE_LOGGING_IN       3
// We have a personaset which we are advertising to the connection
#define CONN_AI_STATE_SENDING_PERSONAS 4
// The connection is waiting for a login, and all personas have been
// received and communicated
#define CONN_AI_STATE_WAITING_FOR_AUTH 5
// We have sent credentials and are waiting for a response
#define CONN_AI_STATE_AUTHENTICATING   6
// Authentication has completed, now we are receiving the offer
#define CONN_AI_STATE_RECEIVE_OFFER    7
// Waiting for ICE to complete
#define CONN_AI_STATE_WAITING_FOR_ICE  8

int connection_init(struct connection *conn, struct flockservice *svc, connectionfn ctl);

// Mark the connection complete. Must not hold mutex!!
void connection_complete(struct connection *conn);
// Mark connection complete... must hold mutex
void connection_complete_unlocked(struct connection *conn);

// Start the connection appliance timeout on the event loop. an
// appliance must be connected before this time or the connection ends
void connection_start_service(struct connection *conn, struct eventloop *el);

// Connect an appliance to this connection, and reset the connection timeout
int connection_connect_appliance(struct connection *conn,
                                 struct applianceinfo *app);
int connection_disconnect_appliance(struct connection *conn);

struct applianceinfo *connection_get_appliance(struct connection *conn);
// Do not hold mutex
int connection_set_persona(struct connection *conn, const unsigned char *persona_id);
// Do not hold mutex
int connection_set_credential(struct connection *conn,
                              const char *credential, size_t credential_sz);

// conn_mutex MUST BE HELD
#define connection_signal_error(conn, err)                              \
  do {                                                                  \
    int __err_ ## __LINE__ = err;                                       \
    if ( (conn)->conn_control((conn), CONNECTION_OP_SIGNAL_ERROR, &__err_ ## __LINE__)  < 0 ) \
      fprintf(stderr, "connection_signal_error: CONNECTION_OP_SIGNAL_ERROR failed\n"); \
  } while (0)

void connection_confirmation_received(struct connection *conn, int has_personas);
void connection_error_received(struct connection *conn, int error_code);

#define CONNOFFER_NO_MORE_LINES       1
#define CONNOFFER_OFFER_COMPLETE      2
#define CONNOFFER_CANDIDATES_COMPLETE 3
#define CONNOFFER_LINE_ERROR     (-1)
#define CONNOFFER_SERVER_ERROR   (-2)
#define CONNOFFER_LINE_RETRIEVED 0
#define CONNOFFER_NO_MORE_SPACE  3
typedef int(*connofferlnfn)(void *, int *, const char **, const char **);
void connection_offer_received(struct connection *conn, int answer_offs,
                               connofferlnfn lines, void *ud);

int connection_send_personas(struct connection *conn, const unsigned char *persona_hash);
// Mutex must be held
int connection_start_authentication(struct connection *conn);

int connection_verify_tx_id(struct connection *conn, const struct stuntxid *txid);
int connection_wants_personas(struct connection *conn);

int connection_is_complete(struct connection *conn);
// Start auth process, must hold mutex
void connection_wait_for_auth(struct connection *conn);

// Mutex must not be held. Writes data into answer buffer. Returns number of bytes written
int connection_write_answer(struct connection *conn, const char *buf, int next_newline);

void connection_complete_client_ice(struct connection *conn);

#endif
