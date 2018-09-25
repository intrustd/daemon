#include <assert.h>

#include "service.h"
#include "appliance.h"
#include "connection.h"

#define OP_CONNECTION_TIMEOUT_EVT            EVT_CTL_CUSTOM
#define OP_CONNECTION_RETRY_AI_CONNECT       (EVT_CTL_CUSTOM + 1)
#define OP_CONNECTION_APP_REQ_SENT           (EVT_CTL_CUSTOM + 2)
#define OP_CONNECTION_PERSONAS_READY         (EVT_CTL_CUSTOM + 3)

static int connection_disconnect_appliance_ex(struct connection *conn, struct applianceinfo *app);
static void connection_do_request_sent(struct connection *conn);
static int connection_write_request(struct fcspktwriter *fcspw, char *req_buf, int *req_sz);
// Start log-in process, must hold mutex
static void connection_start_login(struct connection *conn);
// Start ICE process with offer request, must hold mutex
static void connection_start_receive_offer(struct connection *conn);
static void connection_request_offer(struct connection *conn);
static void connection_next_request(struct connection *conn);

static void connectionfreefn(const struct shared* s, int level) {
  struct connection *conn = STRUCT_FROM_BASE(struct connection, conn_shared, s);
  struct applianceinfo *app;

  fprintf(stderr, "connectionfreefn called at level %d\n", level);

  if ( conn->conn_control )
    conn->conn_control(conn, CONNECTION_OP_RELEASE_WEAK, NULL);
  else
    fprintf(stderr, "connectionfreefn: warning; could not weak-free derived connection type\n");

  if ( level == SHFREE_NO_MORE_REFS ) {
    SAFE_MUTEX_LOCK(&conn->conn_mutex);
    app = conn->conn_appliance;
    conn->conn_appliance = NULL;
    pthread_mutex_unlock(&conn->conn_mutex);

    connection_disconnect_appliance_ex(conn, app);

    if ( conn->conn_personas ) {
      PERSONASFETCHER_UNREF(conn->conn_personas);
      conn->conn_personas = NULL;
    }

    buffer_release(&conn->conn_answer_buffer);

    pthread_mutex_destroy(&conn->conn_mutex);

    if ( conn->conn_control ) {
      conn->conn_control(conn, CONNECTION_OP_RELEASE, NULL);
      conn->conn_control = NULL;
    } else
      fprintf(stderr, "connectionfreefn: warning: could not free derived connection type\n");
  }
}

static void connection_evtfn(struct eventloop *el, int op, void *arg) {
  struct connection *conn;
  struct qdevent *evt = (struct qdevent *) arg;
  struct applianceinfo *app;

  switch ( op ) {
  case OP_CONNECTION_TIMEOUT_EVT:
    conn = STRUCT_FROM_BASE(struct connection, conn_timeout, evt->qde_sub);
    if ( CONN_LOCK(conn) == 0 ) {
      SAFE_MUTEX_LOCK(&conn->conn_mutex);
      if ( conn->conn_control(conn, CONNECTION_OP_TIMEOUT, NULL) < 0 ) {
        fprintf(stderr, "connection_evtfn: CONNECTION_OP_TIMEOUT returns error\n");
      }
      // Release ourselves
      connection_complete_unlocked(conn);
      pthread_mutex_unlock(&conn->conn_mutex);
      SHARED_DEBUG(&conn->conn_shared, "Before timeout unref");
      CONN_UNREF(conn);
      SHARED_DEBUG(&conn->conn_shared, "After timeout unref");
    }
    break;
  case OP_CONNECTION_RETRY_AI_CONNECT:
    fprintf(stderr, "connection_evtfn: Retrying connection\n");
    conn = STRUCT_FROM_BASE(struct connection, conn_ai_retry_connect, evt->qde_sub);
    if ( CONN_LOCK(conn) == 0 ) {
      app = connection_get_appliance(conn);
      fprintf(stderr, "connection_evtfn: got appliance %p\n", app);
      if ( app ) {
        SAFE_MUTEX_LOCK(&conn->conn_mutex); // So we can use conn_ai_retries
        conn->conn_ai_retries++;
        if ( conn->conn_ai_retries >= MAX_CONNECTION_RETRY ) {

          fprintf(stderr, "connection_evtfn: max retries reached in contacting appliance\n");
          if ( conn->conn_control(conn, CONNECTION_OP_TIMEOUT, NULL) < 0 ) {
            fprintf(stderr, "connection_evtfn: CONNECTION_OP_TIMEOUT returns error\n");
          }

          connection_complete_unlocked(conn);
        } else {
          CONN_WREF(conn); // Sending a packet means that we will set the retry clock
          fprintf(stderr, "connection_evtfn: sending because of retry\n");
          if ( app->ai_appliance_fn(app, AI_OP_SEND_PACKET, &conn->conn_outgoing_packet) < 0 ) {
            CONN_WUNREF(conn);
            connection_complete_unlocked(conn);
          }
        }
        pthread_mutex_unlock(&conn->conn_mutex);
        AI_UNREF(app);
      } else
        fprintf(stderr, "connection_evtfn: could not get reference to appliance\n");
      CONN_UNREF(conn); // In response to CONN_LOCK above
    }
    break;
  case OP_CONNECTION_APP_REQ_SENT:
    conn = STRUCT_FROM_BASE(struct connection, conn_outgoing_packet, FCSPKTWRITER_FROM_EVENT(evt));
    if ( CONN_LOCK(conn) == 0 ) {
      SAFE_MUTEX_LOCK(&conn->conn_mutex);
      if ( conn->conn_outgoing_packet.fcspw_sts == 0 ) {
        fprintf(stderr, "connection_evtfn: sent start conn request\n");
        connection_do_request_sent(conn);
      } else {
        fprintf(stderr, "connection_evtfn: send start conn request error: %s\n",
                strerror(-conn->conn_outgoing_packet.fcspw_sts));
        connection_complete_unlocked(conn);
      }
      pthread_mutex_unlock(&conn->conn_mutex);
      CONN_UNREF(conn);
    }
    break;
  case OP_CONNECTION_PERSONAS_READY:
    conn = STRUCT_FROM_BASE(struct connection, conn_personas_ready_evt, evt->qde_sub);
    if ( CONN_LOCK(conn) == 0 ) {
      SAFE_MUTEX_LOCK(&conn->conn_mutex);
      fprintf(stderr, "Connection receives personas\n");
      if ( conn->conn_ai_state == CONN_AI_STATE_LOGGING_IN && conn->conn_personas ) {
        if ( personasfetcher_init_personaswriter(conn->conn_personas,
                                                 &conn->conn_personas_writer) < 0 ) {
          connection_signal_error(conn, CONNECTION_ERR_COULD_NOT_SEND_PERSONAS);
          connection_wait_for_auth(conn);
        } else {
          conn->conn_ai_state = CONN_AI_STATE_SENDING_PERSONAS;

          assert(conn->conn_personas_writer.pw_cps);
          if ( conn->conn_control(conn, CONNECTION_OP_SEND_PERSONAS, NULL) < 0 ) {
            fprintf(stderr, "connection_evtfn: could not send personas\n");
            connection_complete_unlocked(conn);
          }
        }
      }
      pthread_mutex_unlock(&conn->conn_mutex);
      CONN_UNREF(conn);
    }
    break;
  default:
    fprintf(stderr, "connection_evtfn: Invalid op %d\n", op);
  }
}

int connection_init(struct connection *conn, struct flockservice *svc, connectionfn ctl) {
  SHARED_INIT(&conn->conn_shared, connectionfreefn);

  conn->conn_id = 0;
  conn->conn_control = ctl;
  conn->conn_svc = svc;
  conn->conn_el = NULL;
  conn->conn_appliance = NULL;
  conn->conn_personas = NULL;
  conn->conn_ai_state = CONN_AI_STATE_STARTING;
  conn->conn_ai_retries = 0;
  conn->conn_ai_offer_line = 0;
  conn->conn_ai_appliance_ice_complete = 0;
  conn->conn_ai_client_ice_complete = 0;

  memset(conn->conn_persona_id, 0, sizeof(conn->conn_persona_id));
  conn->conn_credential_sz = 0;

  stun_random_tx_id(&conn->conn_start_tx_id);

  fcspktwriter_init(&conn->conn_outgoing_packet, &conn->conn_shared,
                    connection_write_request,
                    OP_CONNECTION_APP_REQ_SENT, connection_evtfn);

  timersub_init_default(&conn->conn_timeout, OP_CONNECTION_TIMEOUT_EVT, connection_evtfn);
  qdevtsub_init(&conn->conn_personas_ready_evt, OP_CONNECTION_PERSONAS_READY, connection_evtfn);

  buffer_init(&conn->conn_answer_buffer);
  conn->conn_answer_offset = 0;

  if ( pthread_mutex_init(&conn->conn_mutex, NULL) != 0 ) {
    fprintf(stderr, "connection_init: could not create connection mutex\n");
    return -1;
  }

  if ( flockservice_new_connection(svc, conn) < 0 ) {
    fprintf(stderr, "connection_init: could not add new connection to flock service\n");
    pthread_mutex_destroy(&conn->conn_mutex);
    conn->conn_control = NULL;
    return -1;
  }

  return 0;
}

int connection_start_authentication(struct connection *conn) {
  struct applianceinfo *app = conn->conn_appliance;
  int ret = 0;

  assert(app);
  AI_REF(app);

  conn->conn_ai_retries = 0;
  conn->conn_ai_state = CONN_AI_STATE_AUTHENTICATING;

  fprintf(stderr, "connection_start_authentication: sending packet\n");
  CONN_WREF(conn); // An outgoing packet references the connection
  if ( app->ai_appliance_fn(app, AI_OP_SEND_PACKET, &conn->conn_outgoing_packet) < 0 ) {
    CONN_WUNREF(conn);
    connection_complete_unlocked(conn);
    ret = -1;
  }

  AI_UNREF(app);
  return ret;
}

int connection_connect_appliance(struct connection *conn,
                                 struct applianceinfo *app) {
  AI_REF(app);

  assert(!conn->conn_appliance);
  conn->conn_appliance = app;
  conn->conn_ai_state = CONN_AI_STATE_STARTING;
  conn->conn_ai_retries = 0;
  timersub_init_from_now(&conn->conn_ai_retry_connect, CONNECTION_APPLIANCE_TIMEOUT,
                         OP_CONNECTION_RETRY_AI_CONNECT,
                         connection_evtfn);

  if ( pthread_mutex_lock(&app->ai_mutex) == 0 ) {
    HASH_ADD(conn_ai_hh, app->ai_connections, conn_id, sizeof(conn->conn_id), conn);
    pthread_mutex_unlock(&app->ai_mutex);

    CONN_WREF(conn);
    if ( app->ai_appliance_fn(app, AI_OP_SEND_PACKET, &conn->conn_outgoing_packet) < 0 ) {
      CONN_WUNREF(conn);
      fprintf(stderr, "connection_connect_appliance: could not send connection\n");
      connection_disconnect_appliance(conn);
      return -1;
    } else
      conn->conn_ai_state = CONN_AI_STATE_WAITING_TO_START;
  } else {
    fprintf(stderr, "connection_connect_appliance: could not lock appliance mutex\n");
    AI_UNREF(app);
    return -1;
  }

  timersub_set_from_now(&conn->conn_timeout, CONNECTION_TIMEOUT);
  CONN_WREF(conn); // for conn_timeout
  CONN_WREF(conn); // for ai_retry_connect
  eventloop_subscribe_timer(conn->conn_el, &conn->conn_timeout);
  eventloop_subscribe_timer(conn->conn_el, &conn->conn_ai_retry_connect);

  return 0;
}

static int connection_disconnect_appliance_ex(struct connection *conn, struct applianceinfo *app) {
  int ret = 0;
  struct connection *existing;

  if ( app ) {
    if ( pthread_mutex_lock(&app->ai_mutex) == 0 ) {
      HASH_FIND(conn_ai_hh, app->ai_connections, &conn->conn_id, sizeof(conn->conn_id), existing);
      if ( existing == conn ) {
        HASH_DELETE(conn_ai_hh, app->ai_connections, conn);

      } else
        ret = -1;
      pthread_mutex_unlock(&app->ai_mutex);
    } else
      ret = -1;

    AI_UNREF(app);
  }

  return ret;
}

int connection_disconnect_appliance(struct connection *conn) {
  struct applianceinfo *app;
  if ( pthread_mutex_lock(&conn->conn_mutex) == 0 ) {
    app = conn->conn_appliance;
    conn->conn_appliance = NULL;
    pthread_mutex_unlock(&conn->conn_mutex);

    return connection_disconnect_appliance_ex(conn, app);
  } return -1;
}

struct applianceinfo *connection_get_appliance(struct connection *conn) {
  struct applianceinfo *ret;
  if ( pthread_mutex_lock(&conn->conn_mutex) == 0 ) {
    ret = conn->conn_appliance;
    AI_REF(ret);
    pthread_mutex_unlock(&conn->conn_mutex);
    return ret;
  } else
    return NULL;
}

int connection_set_persona(struct connection *conn, const unsigned char *persona_id) {
  if ( conn->conn_ai_state == CONN_AI_STATE_WAITING_FOR_AUTH ) {
    memcpy(conn->conn_persona_id, persona_id, sizeof(conn->conn_persona_id));
    return 0;
  } else {
    return -1;
  }
}

int connection_set_credential(struct connection *conn,
                              const char *credential,
                              size_t credential_sz) {
  if ( conn->conn_ai_state == CONN_AI_STATE_WAITING_FOR_AUTH &&
       credential_sz <= sizeof(conn->conn_credential) ) {
    memcpy(conn->conn_credential, credential, credential_sz);
    conn->conn_credential_sz = credential_sz;
    return 0;
  } else {
    return -1;
  }
}

static void connection_reset_retry_timer(struct connection *conn, int millis) {
  timersub_set_from_now(&conn->conn_ai_retry_connect, millis);
  if ( conn->conn_el ) {
    if ( !eventloop_cancel_timer(conn->conn_el, &conn->conn_ai_retry_connect) )
      CONN_WREF(conn); // Grab a new reference if the timer was not set
    eventloop_subscribe_timer(conn->conn_el, &conn->conn_ai_retry_connect);
  }
}

// Retry with exponential backoff
static void connection_reset_retry_timer_exp(struct connection *conn) {
  connection_reset_retry_timer(conn, CONNECTION_APPLIANCE_TIMEOUT << conn->conn_ai_retries);
}

static void connection_do_request_sent(struct connection *conn) {
  if ( conn->conn_control(conn, CONNECTION_OP_APP_REQ_SENT, NULL) < 0 ) {
    fprintf(stderr, "connection_do_request_sent: conn_control hook failed\n");
    connection_complete_unlocked(conn);
  } else {
    switch ( conn->conn_ai_state ) {
    case CONN_AI_STATE_STARTING:
    case CONN_AI_STATE_COMPLETE:
      break;

    case CONN_AI_STATE_WAITING_FOR_ICE:
      // In this state we're waiting for candidates, but we may have
      // an answer bit to send
      //
      // If we have answer, we retry as usual. Otherwise, we wait at a
      // constant rate
      if ( conn->conn_answer_offset < buffer_size(&conn->conn_answer_buffer) )
        connection_reset_retry_timer_exp(conn);
      else {
        // This is how often we will poll the appliance for candidates
        connection_reset_retry_timer(conn, CONNECTION_ICE_COLLECTION_INTERVAL);
      }
      break;

    case CONN_AI_STATE_WAITING_TO_START:
    case CONN_AI_STATE_LOGGING_IN:
    case CONN_AI_STATE_SENDING_PERSONAS:
    case CONN_AI_STATE_WAITING_FOR_AUTH:
    case CONN_AI_STATE_AUTHENTICATING:
    case CONN_AI_STATE_RECEIVE_OFFER:
      connection_reset_retry_timer_exp(conn);
      break;

    default:
      fprintf(stderr, "connection_do_request_sent: invalid state %d\n", conn->conn_ai_state);
      abort();
    }
  }
}

static int connection_write_request(struct fcspktwriter *fcspw, char *req_buf, int *req_sz) {
  struct connection *conn = STRUCT_FROM_BASE(struct connection, conn_outgoing_packet, fcspw);
  struct stunmsg *msg = (struct stunmsg *) req_buf;
  struct stunattr *attr = STUN_FIRSTATTR(msg);
  int max_req_sz = *req_sz, err;

  *req_sz = 0;

  if ( !STUN_IS_VALID(attr, msg, max_req_sz) ) return -1;

  if ( pthread_mutex_lock(&conn->conn_mutex) == 0 ) {
    switch ( conn->conn_ai_state ) {
    case CONN_AI_STATE_STARTING:
    case CONN_AI_STATE_WAITING_TO_START:
    case CONN_AI_STATE_LOGGING_IN:
    case CONN_AI_STATE_SENDING_PERSONAS:
    case CONN_AI_STATE_WAITING_FOR_AUTH:
    case CONN_AI_STATE_AUTHENTICATING:
      fprintf(stderr, "connection_write_request: sending STARTCONN\n");
      STUN_INIT_MSG(msg, STUN_KITE_STARTCONN);
      memcpy(&msg->sm_tx_id, &conn->conn_start_tx_id, sizeof(msg->sm_tx_id));
      STUN_INIT_ATTR(attr, STUN_ATTR_KITE_CONN_ID, sizeof(conn->conn_id));
      if ( !STUN_ATTR_IS_VALID(attr, msg, max_req_sz) ) { err = -1; goto error; }
      *((uint64_t *) STUN_ATTR_DATA(attr)) = htonll(conn->conn_id);

      if ( conn->conn_ai_state == CONN_AI_STATE_AUTHENTICATING ) {
        attr = STUN_NEXTATTR(attr);
        STUN_INIT_ATTR(attr, STUN_ATTR_USERNAME, sizeof(conn->conn_persona_id));
        if ( !STUN_ATTR_IS_VALID(attr, msg, max_req_sz) ) { err = -1; goto error; }
        memcpy((char *) STUN_ATTR_DATA(attr), conn->conn_persona_id, sizeof(conn->conn_persona_id));

        attr = STUN_NEXTATTR(attr);
        STUN_INIT_ATTR(attr, STUN_ATTR_PASSWORD, conn->conn_credential_sz);
        if ( !STUN_ATTR_IS_VALID(attr, msg, max_req_sz) ) { err = -1; goto error; }
        memcpy((char *) STUN_ATTR_DATA(attr), conn->conn_credential, conn->conn_credential_sz);
      }

      STUN_FINISH_WITH_FINGERPRINT(attr, msg, max_req_sz, err);
      break;

    case CONN_AI_STATE_WAITING_FOR_ICE:
    case CONN_AI_STATE_RECEIVE_OFFER:
      fprintf(stderr, "connection_write_request: sending SENDOFFER\n");
      // Write out offer packet
      STUN_INIT_MSG(msg, STUN_KITE_SENDOFFER);
      memcpy(&msg->sm_tx_id, &conn->conn_start_tx_id, sizeof(msg->sm_tx_id));
      STUN_INIT_ATTR(attr, STUN_ATTR_KITE_CONN_ID, sizeof(conn->conn_id));
      if ( !STUN_ATTR_IS_VALID(attr, msg, max_req_sz) ) { err = -1; goto error; }
      *((uint64_t *) STUN_ATTR_DATA(attr)) = htonll(conn->conn_id);

      attr = STUN_NEXTATTR(attr);
      STUN_INIT_ATTR(attr, STUN_ATTR_KITE_SDP_LINE, sizeof(uint16_t));
      if ( !STUN_ATTR_IS_VALID(attr, msg, max_req_sz)) { err = -1; goto error; }
      *((uint16_t *) STUN_ATTR_DATA(attr)) = htons(conn->conn_ai_offer_line);

      // We may also have some bit of answer left to send
      if ( conn->conn_answer_offset < buffer_size(&conn->conn_answer_buffer) ) {
        int space_left = max_req_sz;
        struct stunattr *nextattr = STUN_NEXTATTR(attr);
        fprintf(stderr, "going to write answer in request: %d %lu\n", max_req_sz, STUN_OFFSET(msg, nextattr));
        fprintf(stderr, "writing answer at offset %d (%ld bytes total)\n", conn->conn_answer_offset,
                buffer_size(&conn->conn_answer_buffer));
        if ( space_left > STUN_OFFSET(msg, nextattr) ) {
          space_left -= STUN_OFFSET(msg, nextattr);
          if ( space_left > STUN_FINGERPRINT_GAP ) {
            space_left -= STUN_FINGERPRINT_GAP;

            if ( space_left > 6 && buffer_size(&conn->conn_answer_buffer) > conn->conn_answer_offset ) {
              uint16_t answer_offset = htons(conn->conn_answer_offset);
              int attr_sz = space_left - 4; // subtract 4 for header
              int bytes_to_write = attr_sz - 2; // 2 bytes of offset

              if ( (bytes_to_write + conn->conn_answer_offset) > buffer_size(&conn->conn_answer_buffer) )
                bytes_to_write = buffer_size(&conn->conn_answer_buffer) - conn->conn_answer_offset;

              if ( bytes_to_write > 0 ) {
                attr_sz = bytes_to_write + 2;

                attr = nextattr;
                assert(STUN_IS_VALID(attr, msg, max_req_sz));
                STUN_INIT_ATTR(attr, STUN_ATTR_KITE_ANSWER, attr_sz);
                assert(STUN_ATTR_IS_VALID(attr, msg, max_req_sz));
                memcpy(STUN_ATTR_DATA(attr), &answer_offset, sizeof(answer_offset));
                memcpy(((char *) STUN_ATTR_DATA(attr)) + 2,
                       buffer_data(&conn->conn_answer_buffer, conn->conn_answer_offset),
                       bytes_to_write);
              }
            }
          }
        }
      }

      STUN_FINISH_WITH_FINGERPRINT(attr, msg, max_req_sz, err);
      assert(err == 0);
      break;
    default:
      fprintf(stderr, "connection_write_request: invalid state\n");
      err = -1;
    }

  error:
    pthread_mutex_unlock(&conn->conn_mutex);
    if ( err == 0 ) {
      *req_sz = STUN_MSG_LENGTH(msg);
      return 0;
    } else {
      return -1;
    }
  } else return -1;
}

void connection_offer_received(struct connection *conn, int answer_offs,
                               connofferlnfn lines, void *ud) {
  int next_line, err, request_offer = 0;
  struct sdpln ln;

  fprintf(stderr, "connection offer received %d\n", conn->conn_ai_state);

  CONN_REF(conn);
  SAFE_MUTEX_LOCK(&conn->conn_mutex);

  connection_next_request(conn);

  if ( answer_offs >= 0 )
    conn->conn_answer_offset = answer_offs;

  if ( conn->conn_ai_state == CONN_AI_STATE_RECEIVE_OFFER ||
       conn->conn_ai_state == CONN_AI_STATE_WAITING_FOR_ICE ) {
    fprintf(stderr, "going to send lines\n");
    while ( (err = lines(ud, &next_line, &ln.sl_start, &ln.sl_end)) == CONNOFFER_LINE_RETRIEVED ) {
      fprintf(stderr, "got line %d %d\n", next_line, conn->conn_ai_offer_line);
      if ( next_line == conn->conn_ai_offer_line ) {
        err = conn->conn_control(conn, CONNECTION_OP_SEND_OFFER_LINE, &ln);
        if ( err < 0 ) {
          err = CONNOFFER_SERVER_ERROR;
          break;
        } else if ( err == 0 ) {
          // No more space in send buffer, this was not sent
          err = CONNOFFER_NO_MORE_SPACE;
          break;
        }
        conn->conn_ai_offer_line = next_line + 1;
      } else {
        fprintf(stderr, "connection_offer_received: line discontinuity. Got %d, expected %d\n",
                next_line, conn->conn_ai_offer_line);
        break;
      }
    }

    if ( err == CONNOFFER_OFFER_COMPLETE ||
         err == CONNOFFER_CANDIDATES_COMPLETE ) {
      // There is no more data in the offer. Now, we just want to poll for ice candidates
      // Transition to next state
      if ( conn->conn_ai_state != CONN_AI_STATE_WAITING_FOR_ICE ) {
        if ( conn->conn_control(conn, CONNECTION_OP_COMPLETE_OFFER, NULL) < 0 ) {
          fprintf(stderr, "connection_offer_received: could not complete offer\n");
          connection_complete_unlocked(conn);
          goto done;
        } else
          conn->conn_ai_state = CONN_AI_STATE_WAITING_FOR_ICE;
      }

      if ( err == CONNOFFER_CANDIDATES_COMPLETE ) {
        if ( !conn->conn_ai_appliance_ice_complete ) {
          // There is no more data in the offer *and* no more ice candidates.
          // We should always transition to CONN_AI_STATE_WAITING_FOR_ICE_COMPLETION
          if ( conn->conn_control(conn, CONNECTION_OP_COMPLETE_ICE_CANDIDATES, NULL) < 0 ) {
            fprintf(stderr, "connection_offer_received: could not complete ice candidates\n");
            connection_complete_unlocked(conn);
          } else
            conn->conn_ai_appliance_ice_complete = 1;
        }
      }
    } else if ( err == CONNOFFER_LINE_ERROR ||
                err == CONNOFFER_SERVER_ERROR ) {
      connection_signal_error(conn, err == CONNOFFER_LINE_ERROR ? CONNECTION_ERR_NO_CONNECTION : CONNECTION_ERR_SERVER);
      connection_complete_unlocked(conn);
    } else if ( err == CONNOFFER_NO_MORE_LINES ) {
      // The STUN request was too small to get all the lines

      if ( conn->conn_ai_state == CONN_AI_STATE_RECEIVE_OFFER ) {
        fprintf(stderr, "because we reached the end of the offer, we will ask for more\n");
        request_offer = 1;
      }
    } // No more space.. The connection will let us know wehn to receive more by calling connection_request_offer
  }

 done:
  // Always request an offer if we have not transmitted all of it
  if ( conn->conn_answer_offset < buffer_size(&conn->conn_answer_buffer) )
    request_offer = 1;

  if ( request_offer ) {
    fprintf(stderr, "Resetting retry timer for answer\n");
    connection_reset_retry_timer(conn, CONNECTION_ICE_COLLECTION_INTERVAL);
    //connection_request_offer(conn);
  }

  pthread_mutex_unlock(&conn->conn_mutex);
  CONN_UNREF(conn);
}

// Called after any response was received. Resets the retry timer. Conn_mutex must be held
static void connection_next_request(struct connection *conn) {
  SHARED_DEBUG(&conn->conn_shared, "Before confirmation received");
  if ( eventloop_cancel_timer(conn->conn_el, &conn->conn_ai_retry_connect) )
    CONN_WUNREF(conn);
  SHARED_DEBUG(&conn->conn_shared, "After confirmation received");

  conn->conn_ai_retries = 0;
  stun_random_tx_id(&conn->conn_start_tx_id);
}

void connection_confirmation_received(struct connection *conn, int has_personas) {
  fprintf(stderr, "connection confirmation received\n");
  SAFE_MUTEX_LOCK(&conn->conn_mutex);
  if ( conn->conn_ai_state == CONN_AI_STATE_WAITING_TO_START ) {

    connection_next_request(conn);

    fprintf(stderr, "connection_confirmation_received: has_personas=%d\n", has_personas);

    if ( has_personas ) {
      connection_start_login(conn);
    } else {
      connection_wait_for_auth(conn);
    };
  } else if ( conn->conn_ai_state == CONN_AI_STATE_AUTHENTICATING ) {
    stun_random_tx_id(&conn->conn_start_tx_id);
    connection_start_receive_offer(conn);
  }// If not waiting to start, ignore...

  pthread_mutex_unlock(&conn->conn_mutex);
}

void connection_error_received(struct connection *conn, int error) {
  CONN_REF(conn);
  SAFE_MUTEX_LOCK(&conn->conn_mutex);
  if ( conn->conn_ai_state == CONN_AI_STATE_WAITING_TO_START ||
       conn->conn_ai_state == CONN_AI_STATE_AUTHENTICATING ) {

    connection_next_request(conn);

    if ( conn->conn_ai_state == CONN_AI_STATE_WAITING_TO_START ) {
      connection_signal_error(conn, CONNECTION_ERR_NO_CONNECTION);
      connection_complete_unlocked(conn);
    } else if ( conn->conn_ai_state == CONN_AI_STATE_AUTHENTICATING ) {
      if ( error == STUN_UNAUTHORIZED ) {
        connection_signal_error(conn, CONNECTION_ERR_INVALID_CREDENTIALS);
        connection_wait_for_auth(conn);
      } else {
        connection_signal_error(conn, CONNECTION_ERR_NO_CONNECTION);
        connection_complete_unlocked(conn);
      }
    }
  }
  pthread_mutex_unlock(&conn->conn_mutex);
  CONN_UNREF(conn);
}

void connection_complete(struct connection *conn) {

  SAFE_MUTEX_LOCK(&conn->conn_mutex);
  connection_complete_unlocked(conn);
  pthread_mutex_unlock(&conn->conn_mutex);
}

void connection_complete_unlocked(struct connection *conn) {
  if ( conn->conn_ai_state == CONN_AI_STATE_COMPLETE ) return;

  CONN_REF(conn);

  // Remove the connection from the hash table
  if ( flockservice_finish_connection(conn->conn_svc, conn) < 0 )
    fprintf(stderr, "connectionfreefn: warning: could not finish connection\n");

  conn->conn_ai_state = CONN_AI_STATE_COMPLETE;

  if ( conn->conn_el ) {
    SHARED_DEBUG(&conn->conn_shared, "Before complete");
    if ( eventloop_unsubscribe_timer(conn->conn_el, &conn->conn_ai_retry_connect) )
      CONN_WUNREF(conn);
    if ( eventloop_unsubscribe_timer(conn->conn_el, &conn->conn_timeout) )
      CONN_WUNREF(conn);
    SHARED_DEBUG(&conn->conn_shared, "After complete");
  }

  conn->conn_control(conn, CONNECTION_OP_COMPLETE, NULL);

  CONN_UNREF(conn);
}

int connection_is_complete(struct connection *conn) {
  int ret;
  SAFE_MUTEX_LOCK(&conn->conn_mutex);
  ret = conn->conn_ai_state == CONN_AI_STATE_COMPLETE;
  pthread_mutex_unlock(&conn->conn_mutex);
  return ret;
}

int connection_send_personas(struct connection *conn, const unsigned char *personas_hash) {
  // Ask the service for the personas fetcher for this hash. If we
  // find it, get the personas.
  struct applianceinfo *app;

  if ( pthread_mutex_lock(&conn->conn_mutex) == 0 ) {
    if ( conn->conn_personas ) {
      // If we are already fetching personas, return an error, unless
      // its for the same persona set
      if ( personasfetcher_hash_matches(conn->conn_personas, personas_hash) ) {
        pthread_mutex_unlock(&conn->conn_mutex);
        return 0;
      } else {
        pthread_mutex_unlock(&conn->conn_mutex);
        return -1;
      }
    } else {
      app = conn->conn_appliance;

      // Attempt to find personasfetcher in the caches, or get a
      // reference to a new one if none exists.
      conn->conn_personas = applianceinfo_lookup_personas(app, conn->conn_el, conn->conn_svc,
                                                          personas_hash);
      if ( conn->conn_personas ) {
        // If we got the fetcher, then we're done; just request a notification
        CONN_WREF(conn); // The personas ready evt keeps a weak reference to the connection
        personasfetcher_request_event(conn->conn_personas, conn->conn_el,
                                      &conn->conn_personas_ready_evt);
        pthread_mutex_unlock(&conn->conn_mutex);
        return 0;
      } else {
        pthread_mutex_unlock(&conn->conn_mutex);
        fprintf(stderr, "connection_send_personas: unable to request fetch of persona set\n");
        return -1;
      }
    }
  } else {
    return -1;
  }
}

static void connection_request_offer(struct connection *conn) {
  struct applianceinfo *app = conn->conn_appliance;
  fprintf(stderr, "connection_request_offer called\n");
  CONN_WREF(conn);
  if ( app->ai_appliance_fn(app, AI_OP_SEND_PACKET, &conn->conn_outgoing_packet) < 0 ) {
    CONN_WUNREF(conn);
    connection_complete_unlocked(conn);
  }
}

static void connection_start_login(struct connection *conn) {
  fprintf(stderr, "connection_start_login: starting login\n");
  conn->conn_ai_state = CONN_AI_STATE_LOGGING_IN;
  if ( conn->conn_control(conn, CONNECTION_OP_START_LOGIN, NULL) < 0 ) {
    fprintf(stderr, "conection_start_login: could not start login\n");
    connection_complete_unlocked(conn);
  }
}

void connection_wait_for_auth(struct connection *conn) {
  conn->conn_ai_state = CONN_AI_STATE_WAITING_FOR_AUTH;
  if ( conn->conn_control(conn, CONNECTION_OP_START_AUTH, NULL) < 0 ) {
    fprintf(stderr, "conection_wait_for_auth: could not start auth\n");
    connection_complete_unlocked(conn);
  }
}

static void connection_start_receive_offer(struct connection *conn) {
  if ( conn->conn_ai_state <= CONN_AI_STATE_RECEIVE_OFFER ) {
    conn->conn_ai_state = CONN_AI_STATE_RECEIVE_OFFER;
    if ( conn->conn_control(conn, CONNECTION_OP_START_ICE, NULL) < 0 ) {
      fprintf(stderr, "conection_start_receive_offer: could not start ICE\n");
      connection_complete_unlocked(conn);
    }

    conn->conn_ai_retries = 0;
    conn->conn_ai_offer_line = 0;

    // send the offer request
    connection_request_offer(conn);
  }
}

int connection_verify_tx_id(struct connection *conn, const struct stuntxid *txid) {
  int ret = -1;
  if ( pthread_mutex_lock(&conn->conn_mutex) == 0 ) {
    ret = memcmp(&conn->conn_start_tx_id, txid, sizeof(conn->conn_start_tx_id));
    pthread_mutex_unlock(&conn->conn_mutex);
  }
  return ret;
}

int connection_wants_personas(struct connection *conn) {
  int ret = 0;
  if ( pthread_mutex_lock(&conn->conn_mutex) == 0 ) {
    ret = conn->conn_ai_state == CONN_AI_STATE_LOGGING_IN;
    pthread_mutex_unlock(&conn->conn_mutex);
  }
  return ret;
}

int connection_write_answer(struct connection *conn, const char *buf, int next_newline) {
  int to_write = next_newline;

  if ( (to_write + buffer_size(&conn->conn_answer_buffer)) > MAX_CONNECTION_ANSWER_SZ )
    to_write = MAX_CONNECTION_ANSWER_SZ - buffer_size (&conn->conn_answer_buffer);

  if ( buffer_write(&conn->conn_answer_buffer, buf, next_newline) < 0 ) {
    fprintf(stderr, "connection_write_answer: out of memory\n");
    return -1;
  }

  fprintf(stderr, "connection request offer for answer\n");
  connection_request_offer(conn);

  return to_write;
}

void connection_complete_client_ice(struct connection *conn) {
  conn->conn_ai_client_ice_complete = 1;
}
