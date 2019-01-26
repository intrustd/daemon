#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>

#include "state.h"
#include "websocket.h"
#include "connection.h"

#define OP_WEBSOCKET_EVT EVT_CTL_CUSTOM
#define OP_WEBSOCKET_HAS_MORE_SPACE (EVT_CTL_CUSTOM + 1)

struct wsconnection {
  struct connection wsc_conn;

  int wsc_mode;
  unsigned int wsc_proto_mode : 4;
  unsigned int wsc_corking_mode : 2;
  unsigned int wsc_nl_mode : 2;

  int wsc_websocket;
  struct fdsub wsc_wsk_sub;

  char wsc_pkt_buf[4096];
  int  wsc_pkt_sz;

  char wsc_outgoing_buf[2048];
  int wsc_outgoing_pos, wsc_outgoing_sz;

  struct qdevtsub wsc_has_more_outgoing;
};

#define WSC_MODE_STARTING           1
#define WSC_MODE_HTTP               2
#define WSC_MODE_WEBSOCKET          3
#define WSC_MODE_FLOCKP             4

#define WSC_NO_CORK                 0
#define WSC_START_CORK              1
#define WSC_CONTINUE_CORK           2
#define WSC_FINISH_CORK             3

#define WSC_PROTO_NO_READS          0
#define WSC_PROTO_HANDSHAKE         1
#define WSC_PROTO_GET_APPLIANCE     2
#define WSC_PROTO_LOGIN             3
#define WSC_PROTO_GET_CREDENTIAL    4
#define WSC_PROTO_RECEIVING_ANSWER  5

#define WSC_NL_NONE 0
#define WSC_NL_CR1  1
#define WSC_NL_NL1  2
#define WSC_NL_CR2  3

#define WSC_PROTO_MODE_NEEDS_LINE(mode) ((mode) != WSC_PROTO_RECEIVING_ANSWER)

#define WSC_PROTO_HANDSHAKE_VALUE "start"

#define WSC_REF(wsc)   CONN_REF(&(wsc)->wsc_conn)
#define WSC_WREF(wsc)  CONN_WREF(&(wsc)->wsc_conn)
#define WSC_WUNREF(wsc)  CONN_WUNREF(&(wsc)->wsc_conn)
#define WSC_LOCK(wsc)  CONN_LOCK(&(wsc)->wsc_conn)
#define WSC_UNREF(wsc) CONN_UNREF(&(wsc)->wsc_conn)

#define WSC_SUBSCRIBE_WRITE(wsc) do {                   \
    uint16_t __did_sub ## __LINE__;                     \
    WSC_WREF(wsc); /* For FD_SUB_WRITE */               \
    WSC_WREF(wsc); /* For FD_SUB_ERROR */               \
    __did_sub ## __LINE__ = eventloop_subscribe_fd      \
      ((wsc)->wsc_conn.conn_el, (wsc)->wsc_websocket,   \
       FD_SUB_WRITE | FD_SUB_ERROR,                     \
       &(wsc)->wsc_wsk_sub);                            \
    if ( (__did_sub ## __LINE__ & FD_SUB_WRITE) == 0 )  \
      WSC_WUNREF(wsc);                                  \
    if ( (__did_sub ## __LINE__ & FD_SUB_ERROR) == 0 )  \
      WSC_WUNREF(wsc);                                  \
  } while (0)
#define WSC_SUBSCRIBE_READ(wsc) do {                    \
    uint16_t __did_sub ## __LINE__;                     \
    WSC_WREF(wsc); /* For FD_SUB_READ */                \
    WSC_WREF(wsc); /* For FD_SUB_ERROR */               \
    __did_sub ## __LINE__ = eventloop_subscribe_fd      \
      ((wsc)->wsc_conn.conn_el, (wsc)->wsc_websocket,   \
       FD_SUB_READ | FD_SUB_ERROR,                      \
       &(wsc)->wsc_wsk_sub);                            \
    if ( (__did_sub ## __LINE__ & FD_SUB_READ) == 0 )   \
      WSC_WUNREF(wsc);                                  \
    if ( (__did_sub ## __LINE__ & FD_SUB_ERROR) == 0 )  \
      WSC_WUNREF(wsc);                                  \
  } while (0)

#define WSC_HAS_SPACE(wsc, len) (((wsc)->wsc_outgoing_sz + (len)) <= sizeof((wsc)->wsc_outgoing_buf))
#define WSC_SPACE_LEFT(wsc) (sizeof((wsc)->wsc_outgoing_buf) - (wsc)->wsc_outgoing_sz)
#define WSC_VCF_CHUNK_SZ 128 // Send this many chunks at a time
#define WSC_OVERHEAD     256 // Space to leave in buffer

#define WS_MASK       0x80
#define WS_FIN        0x80
#define WS_TEXT_FRAME 0x01

struct wshs {
  uint32_t ws_flags;
  int      ws_version;
  char     ws_accept_key[32];
  int      ws_accept_key_len;

  const char *ws_loc_start, *ws_loc_end;

  int         ws_error;
};

#define WS_HAS_CONNECTION_UPGRADE 0x1
#define WS_HAS_UPGRADE_WEBSOCKET  0x2
#define WS_HAS_ACCEPT_KEY         0x4

static int wsconnection_init(struct wsconnection *conn, struct flockstate *st, int newsk);
static void wsconnection_start_service(struct wsconnection *conn, struct eventloop *el);
static void wsconnection_respond_line(struct wsconnection *conn, struct eventloop *el, const char *line);
static void wsconnection_respond_line_ex(struct wsconnection *conn, struct eventloop *el, const char *line, size_t length);
static void wsconnection_set_cork(struct wsconnection *conn);
static int wsconnection_write_personas(struct wsconnection *wsc);

// Returns 1 if two nls have been reached, otherwise, updates the
// internal state and returns 0
static int wsconnection_nl_mode(struct wsconnection *wsc, const char *buf, int *sz);

static int parse_ws_handshake(struct wsconnection *wsc, struct wshs *hs, int *req_end);
static void send_http_error(struct wsconnection *wsc, struct wshs *hs);
static void send_handshake_response(struct wsconnection *wsc, struct wshs *hs);

static void wsconnection_set_cork(struct wsconnection *conn) {
  if ( conn->wsc_corking_mode == WSC_NO_CORK )
    conn->wsc_corking_mode = WSC_START_CORK;
}

static void wsconnection_remove_cork(struct wsconnection *conn) {
  if ( conn->wsc_corking_mode >= WSC_START_CORK ) {
    if ( conn->wsc_corking_mode == WSC_CONTINUE_CORK ) {
      conn->wsc_corking_mode = WSC_FINISH_CORK;
      wsconnection_respond_line(conn, conn->wsc_conn.conn_el, "");
    }
    conn->wsc_corking_mode = WSC_NO_CORK;
  }
}

static int wsconnection_write_personas(struct wsconnection *wsc) {
  int bytes_read, bytes_written, bytes_to_read;

  fprintf(stderr, "wsconnection_write_personas: %p %p %d\n",
          wsc, wsc->wsc_conn.conn_personas_writer.pw_cps,
          PERSONASWRITER_IS_VALID(&wsc->wsc_conn.conn_personas_writer));
  assert(PERSONASWRITER_IS_VALID(&wsc->wsc_conn.conn_personas_writer));
  bytes_written = personaswriter_size(&wsc->wsc_conn.conn_personas_writer);

  bytes_to_read = WSC_SPACE_LEFT(wsc) >  bytes_written ?
    WSC_SPACE_LEFT(wsc) : bytes_written;

  bytes_to_read -= WSC_OVERHEAD;

  if ( bytes_to_read > 0 ) {
    char temp_buf[bytes_to_read];
    bytes_read = personaswriter_get_chunk(&wsc->wsc_conn.conn_personas_writer, temp_buf, bytes_to_read);
    if ( bytes_read < bytes_to_read ) { // Complete
      personaswriter_release(&wsc->wsc_conn.conn_personas_writer);
      wsconnection_remove_cork(wsc);
      // Transition connection into another state
    }

    wsconnection_respond_line_ex(wsc, wsc->wsc_conn.conn_el, temp_buf, bytes_read);

    WSC_SUBSCRIBE_WRITE(wsc);
  } else
    return 1;

  return bytes_read < bytes_to_read;
}

void websocket_fn(struct eventloop *el, int op, void *arg) {
  struct flockstate *st;
  int new_sk;
  struct wsconnection *conn;

  intrustd_sock_addr addr;
  unsigned int addr_sz = sizeof(addr);

  st = FLOCKSTATE_FROM_EVENTLOOP(el);

  switch ( op ) {
  case WS_EVENT_ACCEPT:
    new_sk = accept(st->fs_websocket_sk, &addr.sa, &addr_sz);
    if ( new_sk < 0 ) {
      perror("websocket_fn: accept");
      return;
    }
    eventloop_subscribe_fd(el, st->fs_websocket_sk, FD_SUB_ACCEPT, &st->fs_websocket_sub);

    if ( set_socket_nonblocking(new_sk) < 0 ) {
      perror("websocket_fn: set_socket_nonblocking");
      return;
    }

    conn = malloc(sizeof(*conn));
    if ( !conn ) {
      fprintf(stderr, "websocket_fn: Could not create connection\n");
      close(new_sk);
      return;
    }

    if ( wsconnection_init(conn, st, new_sk) < 0 ) {
      fprintf(stderr, "websocket_fn: wsconnection_init fails\n");
      close(new_sk);
      return;
    }

    fprintf(stderr, "Starting websocket service\n");
    wsconnection_start_service(conn, &st->fs_eventloop);

    WSC_UNREF(conn);

    break;
  default:
    fprintf(stderr, "websocket_fn: Unknown op %d\n", op);
  }
}

static int wsconnection_onprotoline(struct wsconnection *wsc, struct eventloop *el,
                                    const char *buf, int next_newline) {
  struct applianceinfo *appliance;
  unsigned char persona_id[SHA256_DIGEST_LENGTH];

  fprintf(stderr, "Got line %.*s\n", next_newline, buf);

  switch ( wsc->wsc_proto_mode ) {
  case WSC_PROTO_HANDSHAKE:
    if ( strcmp_fixed(buf, next_newline,
                      WSC_PROTO_HANDSHAKE_VALUE, static_strlen(WSC_PROTO_HANDSHAKE_VALUE)) == 0 ) {
      wsc->wsc_proto_mode = WSC_PROTO_GET_APPLIANCE;
      fprintf(stderr, "Transitioning to get appliance\n");
      wsconnection_respond_line(wsc, el, "100 Continue");
    } else {
      wsconnection_respond_line(wsc, el, "400 Must use 'start'");
    }
    WSC_SUBSCRIBE_READ(wsc);
    return 0;
  case WSC_PROTO_GET_APPLIANCE:
    if ( flockservice_lookup_appliance_ex(wsc->wsc_conn.conn_svc, buf, next_newline,
                                          &appliance) < 0 ) {
      wsconnection_respond_line(wsc, el, "404 Not Found");
    } else {
      if ( connection_connect_appliance(&wsc->wsc_conn, appliance) < 0 ) {
        wsconnection_respond_line(wsc, el, "500 Internal Server Error");
        connection_complete_unlocked(&wsc->wsc_conn);
        AI_UNREF(appliance);
        return -1;
      } else {
        // We do not send a 100 Continue response because we want to
        // wait for confirmation from the appliance
        // wsconnection_respond_line(wsc, el, "100 Continue");
        wsc->wsc_proto_mode = WSC_PROTO_NO_READS;
      }
      AI_UNREF(appliance);
    }
    WSC_SUBSCRIBE_READ(wsc);
    return 0;
  case WSC_PROTO_LOGIN:
    if ( next_newline == (sizeof(persona_id) * 2) ) {
      if ( parse_hex_str(buf, persona_id, sizeof(persona_id)) < 0 ) {
          wsconnection_respond_line(wsc, el, "400 Invalid persona id");
      } else {
        if ( connection_set_persona(&wsc->wsc_conn, persona_id) < 0 ) {
          wsconnection_respond_line(wsc, el, "500 Internal Server Error");
          connection_complete_unlocked(&wsc->wsc_conn);
          return -1;
        }
        wsc->wsc_proto_mode = WSC_PROTO_GET_CREDENTIAL;
      }
    } else if ( next_newline == 0 ) { // Guest login
      memset(persona_id, 0xFF, sizeof(persona_id));
      if ( connection_set_persona(&wsc->wsc_conn, persona_id) < 0 ) {
        wsconnection_respond_line(wsc, el, "500 Internal Server Error");
        connection_complete_unlocked(&wsc->wsc_conn);
        return -1;
      }
      wsc->wsc_proto_mode = WSC_PROTO_GET_CREDENTIAL;
    } else {
      wsconnection_respond_line(wsc, el, "400 Not enough characters in persona");
    }
    WSC_SUBSCRIBE_READ(wsc);
    return 0;
  case WSC_PROTO_GET_CREDENTIAL:
    if ( connection_set_credential(&wsc->wsc_conn, buf, next_newline) < 0 ) {
      wsconnection_respond_line(wsc, el, "406 Invalid credential");
      WSC_SUBSCRIBE_READ(wsc);
      return 0;
    } else {
      fprintf(stderr, "Websocket: got credential... start uthentication\n");
      if ( connection_start_authentication(&wsc->wsc_conn) < 0 ) {
        wsconnection_respond_line(wsc, el, "500 Internal Server Error");
        connection_complete_unlocked(&wsc->wsc_conn);
        return -1;
      } else {
        wsc->wsc_proto_mode = WSC_PROTO_NO_READS;
        return 0;
      }
    }
  case WSC_PROTO_RECEIVING_ANSWER:
    // In this mode, data is not broken up by lines, but rather is fed
    // straight into the SDP parser
    //
    // This mode ends when we receive two newlines in a row
    //
    // Send the data straight into the receive buffer
    fprintf(stderr, "Received answer data %.*s\n", next_newline, buf);
    if ( !wsc->wsc_conn.conn_ai_client_ice_complete ) {
      if ( wsconnection_nl_mode(wsc, buf, &next_newline) ) { // New line was encountered, and next_newline is updated to reflect that
        wsc->wsc_proto_mode = WSC_PROTO_NO_READS;
        connection_complete_client_ice(&wsc->wsc_conn);
      }

      fprintf(stderr, "Writing answer data \n");
      if ( connection_write_answer(&wsc->wsc_conn, buf, next_newline) < next_newline ) {
        wsconnection_respond_line(wsc, el, "413 Request too large");
      }
    }
    return 0;
  case WSC_PROTO_NO_READS:
    fprintf(stderr, "Received line while input not allowed\n");
    return -1;
  default:
    fprintf(stderr, "Unknown websocket protocol mode %d\n", wsc->wsc_proto_mode);
    return -1;
  }
}

static int wsconnection_onread(struct wsconnection *wsc, struct eventloop *el) {
  int err, bytes_available, http_header_end, next_newline, nl_length;
  struct wshs handshake;

  bytes_available = sizeof(wsc->wsc_pkt_buf) - wsc->wsc_pkt_sz;

  if ( bytes_available > 0 ) {
    err = recv(wsc->wsc_websocket, wsc->wsc_pkt_buf + wsc->wsc_pkt_sz, bytes_available, 0);
    if ( err <= 0 ) {
      if ( errno == EWOULDBLOCK ) {
        fprintf(stderr, "wsconnection_onread: encountered EWOULDBLOCK...\n");
        return 0;
      } else {
        perror("wsconnection_onread: socket error");
        connection_complete_unlocked(&wsc->wsc_conn);
        return -1;
      }
    }

    wsc->wsc_pkt_sz += err;

  try_parse:
    switch ( wsc->wsc_mode ) {
    case WSC_MODE_STARTING:
      // Test the first three letters if they are 'GET', then switch to websockets
      if ( wsc->wsc_pkt_sz >= 3 ) {
        if ( wsc->wsc_pkt_buf[0] == 'G' &&
             wsc->wsc_pkt_buf[1] == 'E' &&
             wsc->wsc_pkt_buf[2] == 'T' ) {
          wsc->wsc_mode = WSC_MODE_HTTP;
        } else
          wsc->wsc_mode = WSC_MODE_FLOCKP;

        goto try_parse;
      }
      break;
    case WSC_MODE_HTTP:
      err = parse_ws_handshake(wsc, &handshake, &http_header_end);
      if ( err == 0 ) {
        const char *real_end = handshake.ws_loc_end;

        //fprintf(stderr, "Going to parse location\n");
        // Remove trailing /s
        while ( *(real_end - 1) == '/' && (real_end - 1) > handshake.ws_loc_start )
          real_end--;

        //        fprintf(stderr, "Got location %ld\n", real_end - handshake.ws_loc_start);
        // fprintf(stderr, "Location %.*s\n", (int) (real_end - handshake.ws_loc_start), handshake.ws_loc_start);

        // Success, write out response
        if( handshake.ws_loc_start == real_end ||
            *handshake.ws_loc_start != '/' ) {
	  fprintf(stderr, "Invalid location '%.*s'\n", (int) (real_end - handshake.ws_loc_start), handshake.ws_loc_start);
          handshake.ws_error = 400;
          send_http_error(wsc, &handshake);
          connection_complete_unlocked(&wsc->wsc_conn);
        } else {
          char appliance_name[INTRUSTD_APPLIANCE_NAME_MAX];
          struct applianceinfo *appliance;

          if ( uri_decode(handshake.ws_loc_start + 1, real_end - handshake.ws_loc_start - 1,
                          appliance_name, sizeof(appliance_name)) == 0 ) {
            if ( flockservice_lookup_appliance(wsc->wsc_conn.conn_svc, appliance_name, &appliance) < 0 ) {
              handshake.ws_error = 404;
              send_http_error(wsc, &handshake);
              connection_complete_unlocked(&wsc->wsc_conn);
            } else {

              fprintf(stderr, "Connected to appliance %s\n", appliance_name);

              if ( connection_connect_appliance(&wsc->wsc_conn, appliance) < 0 ) {
                handshake.ws_error = 500;
                send_http_error(wsc, &handshake);
                connection_complete_unlocked(&wsc->wsc_conn);
              } else {
                fprintf(stderr, "wsconnection_onread: http_header_end = %d (total size %d)\n", http_header_end, wsc->wsc_pkt_sz);
                wsc->wsc_pkt_sz -= http_header_end;
                memcpy(wsc->wsc_pkt_buf, wsc->wsc_pkt_buf + http_header_end, wsc->wsc_pkt_sz);
                send_handshake_response(wsc, &handshake);
                wsc->wsc_mode = WSC_MODE_WEBSOCKET;
                wsc->wsc_proto_mode = WSC_PROTO_LOGIN;
                WSC_SUBSCRIBE_READ(wsc);
              }

              AI_UNREF(appliance);
            }
          } else {
	    fprintf(stderr, "Invalid URI encoding '%.*s'\n", (int) (real_end - handshake.ws_loc_start), handshake.ws_loc_start);
            handshake.ws_error = 400;
            send_http_error(wsc, &handshake);
            connection_complete_unlocked(&wsc->wsc_conn);
          }
        }
      } else if ( err > 0 ) {
        // Need more
        fprintf(stderr, "Need more HTTP data\n");
        WSC_SUBSCRIBE_READ(wsc);
      } else {
        // Actual error
        send_http_error(wsc, &handshake);
        connection_complete_unlocked(&wsc->wsc_conn);
      }
      break;
    case WSC_MODE_WEBSOCKET:
      // Read the next websocket frame, if available
      while ( wsc->wsc_pkt_sz > 1 ) {
        unsigned int wsc_len = ((unsigned char) wsc->wsc_pkt_buf[1]) & ~WS_MASK;
        int mask_offs = 2, i = 0;
        unsigned char masking[4];

        fprintf(stderr, "wsconnection_onread: got buffer: %02x %02x\n", (unsigned char)wsc->wsc_pkt_buf[0], (unsigned char) wsc->wsc_pkt_buf[1]);

        if ( (wsc->wsc_pkt_buf[1] & WS_MASK) == 0 ) {
          fprintf(stderr, "wsconnection_onread: masking bit must be set in client-to-server communication: %02x %02x\n", wsc->wsc_pkt_buf[0], wsc->wsc_pkt_buf[1]);
          connection_complete_unlocked(&wsc->wsc_conn);
          return -1;
        }

        if ( (wsc->wsc_pkt_buf[0] & WS_FIN) == 0 ) {
          fprintf(stderr, "wsconnection_onread: TODO fragmented websocket packet\n");
          connection_complete_unlocked(&wsc->wsc_conn);
          return -1;
        }

        if ( wsc_len == 126 ) {
          if ( wsc->wsc_pkt_sz >= 4 ) {
            uint16_t wsc_len16;
            memcpy(&wsc_len16, &wsc->wsc_pkt_buf[2], sizeof(wsc_len16));
            wsc_len = ntohs(wsc_len16);
            mask_offs = 4;
          } else break;

          if ( (wsc_len + 8) > sizeof(wsc->wsc_pkt_buf) ) {
            fprintf(stderr, "wsconnection_onread: not enough space in packet buffer for this packet\n");
            connection_complete_unlocked(&wsc->wsc_conn);
            return -1;
          }
        } else if ( wsc_len == 127 ) {
          mask_offs = 2;
          fprintf(stderr, "wsconnection_onread: Incredibly large packet in websocket. Closing connection\n");
          connection_complete_unlocked(&wsc->wsc_conn);
          return -1;
        }

        if ( wsc->wsc_pkt_sz >= 8 )
          memcpy(&masking, &wsc->wsc_pkt_buf[mask_offs], sizeof(masking));
        else break;

        if ( (wsc_len + mask_offs + sizeof(masking)) > wsc->wsc_pkt_sz ) {
          fprintf(stderr, "wsconnection_onread: need more websocket data for frame: %d %d %zu %d\n",
                  wsc_len, mask_offs, sizeof(masking), wsc->wsc_pkt_sz);
          break;
        }

        // Otherwise we have enough data, but we need to unmask all
        // the data in the buffer. First set the masking key to zero
        // (in case we need to reread the data)
        memset(&wsc->wsc_pkt_buf[mask_offs], 0, 4);

        for ( i = 0; i < wsc_len; ++ i )
          wsc->wsc_pkt_buf[i + mask_offs + 4] ^= masking[i % 4];

        // Now interpret packet
        if ( wsconnection_onprotoline(wsc, el, &wsc->wsc_pkt_buf[mask_offs + 4], wsc_len) < 0 ) {
          connection_complete_unlocked(&wsc->wsc_conn);
          return -1;
        } else {
          wsc->wsc_pkt_sz -= mask_offs + 4 + wsc_len;
          memcpy(wsc->wsc_pkt_buf, wsc->wsc_pkt_buf + mask_offs + 4 + wsc_len,
                 wsc->wsc_pkt_sz);
        }
      }
      break;
    case WSC_MODE_FLOCKP:
      while ( wsc->wsc_pkt_sz > 0 ) {
        if ( WSC_PROTO_MODE_NEEDS_LINE(wsc->wsc_proto_mode) )
          find_newline(wsc->wsc_pkt_buf, wsc->wsc_pkt_sz, &next_newline, &nl_length);
        else {
          // When no line breaking is needed, then the entire buffer is passed in
          next_newline = wsc->wsc_pkt_sz;
          nl_length = 0;
        }

        if ( next_newline >= 0 ) {
          if ( wsconnection_onprotoline(wsc, el, wsc->wsc_pkt_buf, next_newline) < 0 ) {
            connection_complete_unlocked(&wsc->wsc_conn);
            return -1;
          } else {
            wsc->wsc_pkt_sz -= next_newline + nl_length;
            memcpy(wsc->wsc_pkt_buf, wsc->wsc_pkt_buf + next_newline + nl_length,
                   wsc->wsc_pkt_sz);
          }
        } else break;
      }
      break;
    default:
      fprintf(stderr, "wsconnection_onread: unknown mode %d\n", wsc->wsc_mode);
      connection_complete_unlocked(&wsc->wsc_conn);
      return -1;
    }
  } else {
    fprintf(stderr, "wsconnection_onread: buffer overflow\n");
    connection_complete_unlocked(&wsc->wsc_conn);
    return -1;
  }

  return 0;
}

static int wsconnection_dowrite(struct wsconnection *wsc, struct eventloop *el) {
  int err;

  // Return early if there's nothing to write so as not to unref on a
  // connection that was never written to.
  if ( wsc->wsc_outgoing_sz == 0 ) return 0;

  while ( wsc->wsc_outgoing_sz > 0 ) {
    int buf_end = (wsc->wsc_outgoing_pos + wsc->wsc_outgoing_sz) % sizeof(wsc->wsc_outgoing_buf);
    int size_left = buf_end > wsc->wsc_outgoing_pos ? buf_end - wsc->wsc_outgoing_pos :
      sizeof(wsc->wsc_outgoing_buf) - wsc->wsc_outgoing_pos;

    //    fprintf(stderr, "dowrite %d\n", size_left);

    err = send(wsc->wsc_websocket, wsc->wsc_outgoing_buf + wsc->wsc_outgoing_pos, size_left, 0);
    if ( err < 0 ) {
      if ( err == EAGAIN || err == EWOULDBLOCK ) {
        fprintf(stderr, "Can't send enough on socket\n");
        break;
      } else {
        perror("wsconnection_dowrite: send");
        WSC_UNREF(wsc); // Get rid of any writes
        wsc->wsc_outgoing_sz = 0;
        connection_complete(&wsc->wsc_conn);
        return -1;
      }
    }

    //    fprintf(stderr, "Wrote %d characters\n", err);
    SHARED_DEBUG(&wsc->wsc_conn.conn_shared, "After send() syscall");

    wsc->wsc_outgoing_pos += err;
    wsc->wsc_outgoing_sz -= err;

    wsc->wsc_outgoing_pos %= sizeof(wsc->wsc_outgoing_buf);
  }

  if ( wsc->wsc_outgoing_sz == 0 ) {
    if ( eventloop_queue(el, &wsc->wsc_has_more_outgoing) )
      WSC_WREF(wsc);

    WSC_UNREF(wsc);
    SHARED_DEBUG(&wsc->wsc_conn.conn_shared, "wsconnection_dowrite done");
  } else {
    fprintf(stderr, "wsconnection_dowrite %d left\n", wsc->wsc_outgoing_sz);
  }

  return 0;
}

static void wsconnectionfn(struct eventloop *el, int op, void *arg) {
  struct fdevent *fde = (struct fdevent *) arg;
  struct qdevent *qde = (struct qdevent *) arg;
  struct wsconnection *wsc;
  int locked = 0;

  switch ( op ) {
  case OP_WEBSOCKET_EVT:
    wsc = STRUCT_FROM_BASE(struct wsconnection, wsc_wsk_sub, fde->fde_sub);
    SHARED_DEBUG(&wsc->wsc_conn.conn_shared, "wsconnectionfn starting");


    if ( FD_WRITE_AVAILABLE(fde) && WSC_LOCK(wsc) == 0 ) {
      // Writes are controlled via a strong reference (wsconnection_respond_buffer)
      // and a weak reference WSC_SUBSCRIBE_FD
      fprintf(stderr, "Doing write\n");

      SAFE_MUTEX_LOCK(&wsc->wsc_conn.conn_mutex);
      locked = 1;
      WSC_REF(wsc);

      SHARED_DEBUG(&wsc->wsc_conn.conn_shared, "wsconnectionfn calling dowrite");
      if ( wsconnection_dowrite(wsc, el) < 0 ) {
        pthread_mutex_unlock(&wsc->wsc_conn.conn_mutex);
        WSC_UNREF(wsc); // WSC_REF above
        WSC_UNREF(wsc); // WSC_LOCK in condition
        return;
      }

      WSC_UNREF(wsc); // WSC_LOCK in condition
    }

    if ( FD_READ_PENDING(fde) && WSC_LOCK(wsc) == 0 ) {
      fprintf(stderr, "Doing read\n");
      if ( !locked ) {
        SAFE_MUTEX_LOCK(&wsc->wsc_conn.conn_mutex);
        WSC_REF(wsc);
        locked = 1;
      }

      if ( wsc->wsc_conn.conn_ai_state == CONN_AI_STATE_COMPLETE ) {
        fprintf(stderr, "Ignoring websocket event because we are complete\n");
        SHARED_DEBUG(&wsc->wsc_conn.conn_shared, "wsconnectionfn: complete");
        pthread_mutex_unlock(&wsc->wsc_conn.conn_mutex);
        WSC_UNREF(wsc); // In response to WSC_LOCK above
        WSC_UNREF(wsc); // In response to WSC_REF for lock
      } else {
        if ( wsconnection_onread(wsc, el) < 0 ) {
          pthread_mutex_unlock(&wsc->wsc_conn.conn_mutex);
          WSC_UNREF(wsc); // In response to WSC_LOCK above
          WSC_UNREF(wsc); // In response to WSC_REF for lock
          return;
        }
      }

      WSC_UNREF(wsc); // In response to WSC_LOCK above
    }

    if ( FD_ERROR_PENDING(fde) && WSC_LOCK(wsc) == 0 ) {
      fprintf(stderr, "Got HUP on websocket\n");
      WSC_REF(wsc);
      if ( !locked ) {
        SAFE_MUTEX_LOCK(&wsc->wsc_conn.conn_mutex);
        WSC_REF(wsc);
        locked = 1;
      }
      connection_complete_unlocked(&wsc->wsc_conn);
      WSC_UNREF(wsc); // WSC_LOCK above
    }

    fprintf(stderr, "wsconnectionfn: done handling %d\n", locked);
    SHARED_DEBUG(&wsc->wsc_conn.conn_shared, "after done handling");
    if ( locked ) {
      if ( wsc->wsc_conn.conn_ai_state != CONN_AI_STATE_COMPLETE ) {
        if ( wsc->wsc_proto_mode != WSC_PROTO_NO_READS )
          WSC_SUBSCRIBE_READ(wsc);
        if ( wsc->wsc_outgoing_sz > 0 )
          WSC_SUBSCRIBE_WRITE(wsc);
      }

      SHARED_DEBUG(&wsc->wsc_conn.conn_shared, "after request processing");

      pthread_mutex_unlock(&wsc->wsc_conn.conn_mutex);
      WSC_UNREF(wsc); // In response to lock acquired during mutex lock
    }
    break;
  case OP_WEBSOCKET_HAS_MORE_SPACE:
    wsc = STRUCT_FROM_BASE(struct wsconnection, wsc_has_more_outgoing, qde->qde_sub);
    if ( WSC_LOCK(wsc) == 0 ) {
      if ( pthread_mutex_lock(&wsc->wsc_conn.conn_mutex) == 0 ) {
        int finished = 0;
        if ( wsc->wsc_conn.conn_ai_state == CONN_AI_STATE_SENDING_PERSONAS ) {
          if ( PERSONASWRITER_IS_VALID(&wsc->wsc_conn.conn_personas_writer) ) {
            finished = wsconnection_write_personas(wsc);
          }
        }

        if ( finished )
          connection_wait_for_auth(&wsc->wsc_conn);
        pthread_mutex_unlock(&wsc->wsc_conn.conn_mutex);
      }
      WSC_UNREF(wsc);
    }
    break;
  default:
    fprintf(stderr, "wsconnectionfn: Unknown op %d\n", op);
  }
}

static int wsconnectionctlfn(struct connection *c, int op, void *arg) {
  struct wsconnection *wsc = STRUCT_FROM_BASE(struct wsconnection, wsc_conn, c);
  struct sdpln *ln;
  uint16_t old_subs;

  switch ( op ) {
    // Mutex is held
  case CONNECTION_OP_COMPLETE:
    return 0;

  case CONNECTION_OP_RELEASE_WEAK:
    fprintf(stderr, "wsconnectionctlfn: closing websocket\n");
    SAFE_MUTEX_LOCK(&wsc->wsc_conn.conn_mutex);
    if ( wsc->wsc_websocket != 0 ) {
      int old_sk = wsc->wsc_websocket;
      wsc->wsc_websocket = 0;
      old_subs = eventloop_unsubscribe_fd(wsc->wsc_conn.conn_el, old_sk,
                                          FD_SUB_ALL, &wsc->wsc_wsk_sub);
      pthread_mutex_unlock(&wsc->wsc_conn.conn_mutex); // Must unlock here, since the WSC_UNREFs below can result in a full release being done
      if ( old_subs & FD_SUB_READ )
        WSC_WUNREF(wsc);
      if ( old_subs & FD_SUB_WRITE )
        WSC_WUNREF(wsc);
      if ( old_subs & FD_SUB_ERROR )
        WSC_WUNREF(wsc);
      SHARED_DEBUG(&wsc->wsc_conn.conn_shared, "After close");
      close(old_sk);
    } else
      pthread_mutex_unlock(&wsc->wsc_conn.conn_mutex);
    return 0;

  case CONNECTION_OP_RELEASE:
    fprintf(stderr, "wsconnectionctlfn: cleaning up\n");
    return 0;

    // conn_mutex is not held
  case CONNECTION_OP_APP_REQ_SENT:
    return 0;

    // conn_mutex is held
  case CONNECTION_OP_TIMEOUT:
    wsconnection_respond_line(wsc, wsc->wsc_conn.conn_el, "408 Request Timeout");
    WSC_SUBSCRIBE_WRITE(wsc);
    return 0;

    // conn_mutex is held
  case CONNECTION_OP_START_AUTH:
  case CONNECTION_OP_START_LOGIN:
  case CONNECTION_OP_START_ICE:
    if ( op == CONNECTION_OP_START_LOGIN )
      wsconnection_respond_line(wsc, wsc->wsc_conn.conn_el, "105 Fetching Personas");
    else if ( op == CONNECTION_OP_START_AUTH ) {
      wsconnection_respond_line(wsc, wsc->wsc_conn.conn_el, "403 Authenticate Now");
      wsc->wsc_proto_mode = WSC_PROTO_LOGIN;
    } else {
      wsconnection_respond_line(wsc, wsc->wsc_conn.conn_el, "200 Begin ICE");
      wsc->wsc_proto_mode = WSC_PROTO_RECEIVING_ANSWER;
      wsconnection_set_cork(wsc);
    }
    WSC_SUBSCRIBE_WRITE(wsc);
    return 0;

    // conn_muetx is held
  case CONNECTION_OP_SIGNAL_ERROR:
    wsconnection_remove_cork(wsc);
    switch ( *((int *) arg) ) {
    case CONNECTION_ERR_COULD_NOT_SEND_PERSONAS:
      wsconnection_respond_line(wsc, wsc->wsc_conn.conn_el, "503 Personas Not Available");
      break;
    case CONNECTION_ERR_NO_CONNECTION:
      wsconnection_respond_line(wsc, wsc->wsc_conn.conn_el, "502 Appliance rejected connection");
      break;
    case CONNECTION_ERR_INVALID_CREDENTIALS:
      wsconnection_respond_line(wsc, wsc->wsc_conn.conn_el, "401 Unauthorized");
      break;
    case CONNECTION_ERR_SERVER:
      wsconnection_respond_line(wsc, wsc->wsc_conn.conn_el, "500 Internal Server Error");
      break;
    default:
      wsconnection_respond_line(wsc, wsc->wsc_conn.conn_el, "500 Internal Server Error");
      break;
    }
    WSC_SUBSCRIBE_WRITE(wsc);
    return 0;

    // conn_mutex is held
  case CONNECTION_OP_SEND_OFFER_LINE:
    ln = (struct sdpln *)arg;
    if ( WSC_HAS_SPACE(wsc, ln->sl_end - ln->sl_start) ) {
      // If we have space, write the line
      wsconnection_respond_line_ex(wsc, wsc->wsc_conn.conn_el, ln->sl_start, ln->sl_end - ln->sl_start);
      if ( wsc->wsc_mode == WSC_MODE_WEBSOCKET )
        wsconnection_respond_line_ex(wsc, wsc->wsc_conn.conn_el, "\r\n", 2);
      WSC_SUBSCRIBE_WRITE(wsc);
      return 1;
    } else {
      return 0;
    }
    return -1;

    // conn_mutex is held
  case CONNECTION_OP_COMPLETE_ICE_CANDIDATES:
  case CONNECTION_OP_COMPLETE_OFFER:
    wsconnection_remove_cork(wsc);
    fprintf(stderr, "offer completed... removed cork\n");
    if ( op == CONNECTION_OP_COMPLETE_OFFER )
      wsconnection_respond_line(wsc, wsc->wsc_conn.conn_el, "150 Offer Complete");
    else
      wsconnection_respond_line(wsc, wsc->wsc_conn.conn_el, "151 Candidates Complete");
    WSC_SUBSCRIBE_WRITE(wsc);
    return 0;

    // conn_mutex is held
  case CONNECTION_OP_SEND_PERSONAS:
    // We start sending personas by adding a 'cork'. This has no
    // effect for flock protocol connections, but causes the FIN bit
    // to be unset on all websocket ones.
    //
    // Then we use the personaswriter to read WSC_VCF_CHUNK_SIZE bytes
    // at most into the temporary buffer
    //
    // We then request a write. The write function will return how
    // many bytes were actually written. If this number is less than
    // WSC_VCF_CHUNK_SIZE we stop. Otherwise, we subscribe to the write
    // event.

    WSC_REF(wsc);

    if ( PERSONASWRITER_IS_VALID(&wsc->wsc_conn.conn_personas_writer) ) {
      wsconnection_set_cork(wsc);
      if ( wsconnection_write_personas(wsc) )
        connection_wait_for_auth(&wsc->wsc_conn);
      }

    WSC_UNREF(wsc);
    return 0;

  default:
    fprintf(stderr, "wsconnectionctlfn: Unknown op %d\n", op);
    return -2;
  }
}

static int wsconnection_init(struct wsconnection *conn, struct flockstate *st, int newsk) {
  conn->wsc_mode = WSC_MODE_STARTING;
  conn->wsc_proto_mode = WSC_PROTO_HANDSHAKE;
  conn->wsc_corking_mode = WSC_NO_CORK;
  conn->wsc_nl_mode = WSC_NL_NONE;
  conn->wsc_websocket = newsk;

  fdsub_init(&conn->wsc_wsk_sub, &st->fs_eventloop, conn->wsc_websocket,
             OP_WEBSOCKET_EVT, wsconnectionfn);
  qdevtsub_init(&conn->wsc_has_more_outgoing, OP_WEBSOCKET_HAS_MORE_SPACE, wsconnectionfn);

  conn->wsc_pkt_sz = 0;
  conn->wsc_outgoing_pos = 0;
  conn->wsc_outgoing_sz = 0;

  return connection_init(&conn->wsc_conn, &st->fs_service, wsconnectionctlfn);
}

static void wsconnection_start_service(struct wsconnection *conn, struct eventloop *el) {
  conn->wsc_conn.conn_el = el;
  WSC_SUBSCRIBE_READ(conn);
  SHARED_DEBUG(&conn->wsc_conn.conn_shared, "after start");
}

static void wsconnection_respond_line(struct wsconnection *conn, struct eventloop *el,
                                      const char *line_nonl) {
  wsconnection_respond_line_ex(conn, el, line_nonl, strlen(line_nonl));
}

static void wsconnection_respond_buffer(struct wsconnection *conn, struct eventloop *el,
                                        const char *line, int line_length) {
  int bytes_left = line_length;

  if ( conn->wsc_mode != WSC_MODE_WEBSOCKET )
    fprintf(stderr, "wsconnection_respond_line: %.*s", line_length, line);
  else
    fprintf(stderr, "wsconnection_respond_line: Writing websocket data of length %d\n", line_length);

  if ( !WSC_HAS_SPACE(conn, line_length) ) {
    fprintf(stderr, "wsconnection_respond_line: overflow\n");
    connection_complete(&conn->wsc_conn);
    return;
  }

  if ( conn->wsc_outgoing_sz == 0 ) {
    WSC_REF(conn);
    SHARED_DEBUG(&conn->wsc_conn.conn_shared, "After referencing in write line");
  }

  while ( bytes_left > 0 ) {
    int buf_end = (conn->wsc_outgoing_pos + conn->wsc_outgoing_sz) % sizeof(conn->wsc_outgoing_buf);
    int space_available = (buf_end >= conn->wsc_outgoing_pos) ?
      sizeof(conn->wsc_outgoing_buf) - buf_end :
      conn->wsc_outgoing_pos - buf_end;

    int to_write = space_available > bytes_left ? bytes_left : space_available;

    assert(space_available > 0);

    fprintf(stderr, "wsconn_write at %d of length %d\n", buf_end, to_write);
    memcpy(conn->wsc_outgoing_buf + buf_end,
           line, to_write);

    bytes_left -= to_write;
    conn->wsc_outgoing_sz += to_write;
  }

  fprintf(stderr, "after write %d %d\n", conn->wsc_outgoing_pos, conn->wsc_outgoing_sz);
}

static void wsconnection_respond_protoline(struct wsconnection *conn, struct eventloop *el,
                                           const char *line_nonl, size_t line_nonl_length) {
  int line_length = line_nonl_length + 2;
  char line[line_length];

  memcpy(line, line_nonl, line_nonl_length);
  line[line_length - 2] = '\r';
  line[line_length - 1] = '\n';
  wsconnection_respond_buffer(conn, el, line, line_length);
}

static void wsconnection_respond_wsline(struct wsconnection *conn, struct eventloop *el,
                                        const char *line_nonl, size_t line_nonl_length) {
  // We never fragment anything ever
  int line_length = line_nonl_length + 10, cur_pkt_length = 0;
  char line[line_length];

  if ( conn->wsc_corking_mode == WSC_START_CORK ) {
    line[0] = WS_TEXT_FRAME;
    conn->wsc_corking_mode = WSC_CONTINUE_CORK;
  } else if ( conn->wsc_corking_mode == WSC_CONTINUE_CORK )
    line[0] = 0;
  else if ( conn->wsc_corking_mode == WSC_FINISH_CORK ) {
    line[0] = WS_FIN;
    conn->wsc_corking_mode = WSC_NO_CORK;
  } else
    line[0] = WS_FIN | WS_TEXT_FRAME;

  cur_pkt_length = 1;
  if ( line_nonl_length < 126 ) {
    line[1] = line_nonl_length;
    cur_pkt_length++;
  } else {
    uint16_t line_length16 = htons(line_nonl_length);
    line[1] = 126;
    cur_pkt_length ++;
    // Next two bytes are the length
    memcpy(&line[2], &line_length16, sizeof(line_length16));
    cur_pkt_length += sizeof(line_length16);
  }

  memcpy(&line[cur_pkt_length], line_nonl, line_nonl_length);
  cur_pkt_length += line_nonl_length;

  wsconnection_respond_buffer(conn, el, line, cur_pkt_length);
}

static void wsconnection_respond_line_ex(struct wsconnection *conn, struct eventloop *el,
                                         const char *line_nonl, size_t line_nonl_length) {
  switch ( conn->wsc_mode ) {
  case WSC_MODE_WEBSOCKET:
    wsconnection_respond_wsline(conn, el, line_nonl, line_nonl_length);
    break;
  default:
  case WSC_MODE_STARTING:
  case WSC_MODE_FLOCKP:
  case WSC_MODE_HTTP:
    wsconnection_respond_protoline(conn, el, line_nonl, line_nonl_length);
    break;
  }
}

// Straightforwards http parser

#define HTTP_PS_VERB          1
#define HTTP_PS_LOCATION      2
#define HTTP_PS_VERSION       3
#define HTTP_PS_HEADER_OR_END 4
#define HTTP_PS_HEADER_NAME   5
#define HTTP_PS_HEADER_COLON  6
#define HTTP_PS_HEADER_VALUE  7
#define HTTP_PS_END           8

#define HTTP_NEXT_CHAR  bytes_left--; buf++
#define HTTP_SKIP_SPACE while ( bytes_left > 0 && *buf == ' ' ) { HTTP_NEXT_CHAR; }
#define HTTP_CONSUME_NEWLINE do {               \
  if ( *buf == '\r' ) {                         \
    HTTP_NEXT_CHAR;                             \
    if ( bytes_left > 0 ) {                     \
      if ( *buf == '\n' ) {                     \
        HTTP_NEXT_CHAR;                         \
      } else {                                  \
        hs->ws_error = 400;                     \
        return -1;                              \
      }                                         \
    } else {                                    \
      return 1;                                 \
    }                                           \
  } else {                                      \
    hs->ws_error = 400;                         \
    return -1;                                  \
  } } while (0)

static void trim(const char **s, const char **e) {
  while ( *s < *e ) {
    fprintf(stderr, "trim %p %p %p %p\n", s, e, *s, *e);
    if ( isspace(**s) ) {
      (*s)++;
    } else if ( isspace(**e) ) {
      (*e)--;
    } else {
      fprintf(stderr, "break\n");
      break;
    }
  }

  if ( *e < *s ) {
    *e = *s;
  }
}

static int has_upgrade(const char *vls, const char *vle) {
  const char *next;

  while ( vls < vle && (next = memchr(vls, ',', vle - vls)) ) {
    trim(&vls, &next);

    fprintf(stderr, "Upgrade check: %.*s\n", (int)(next - vls), vls);
    if ( strncasecmp(vls, "upgrade", next - vls) == 0 )
      return 1;

    vls = next + 1;
  }

  if ( vls < vle ) {
    trim(&vls, &vle);
    fprintf(stderr, "Upgrade check: %.*s\n", (int)(vle - vls), vls);
    if ( strncasecmp(vls, "upgrade", vle - vls) == 0 )
      return 1;
  }

  return 0;
}

static int parse_http_header(struct wshs *hs, const char *nms, const char *nme,
                             const char *vls, const char *vle) {
  if ( strncasecmp(nms, "connection", nme - nms) == 0 ) {
    if ( has_upgrade(vls, vle) ) {
      hs->ws_flags |= WS_HAS_CONNECTION_UPGRADE;
      return 0;
    } else {
      fprintf(stderr, "parse_http_header: invalid connection header %.*s\n", (int) (vle - vls), vls);
      hs->ws_error = 400;
      return -1;
    }
  } else if ( strncasecmp(nms, "upgrade", nme - nms) == 0 ) {
    if ( strncasecmp(vls, "websocket", vle - vls) == 0 ) {
      hs->ws_flags |= WS_HAS_UPGRADE_WEBSOCKET;
      return 0;
    } else {
      fprintf(stderr, "parse_http_header: invalid upgrade header %.*s\n", (int) (vle - vls), vls);
      hs->ws_error = 400;
      return -1;
    }
  } else if ( strncasecmp(nms, "sec-websocket-version", nme - nms) == 0 ) {
    const char *cur = vls;
    hs->ws_version = 0;
    if ( vle == vls ) {
      fprintf(stderr, "parse_http_header: empty sec-websocket-version\n");
      hs->ws_error = 400;
      return -1;
    } else {
      for ( ; cur != vle; ++cur ) {
        if ( *cur >= '0' && *cur <= '9' ) {
          hs->ws_version *= 10;
          hs->ws_version += (*cur - '0');
        } else {
	  fprintf(stderr, "parse_http_header: non-digit in sec-websocket-version\n");
          hs->ws_error = 400;
          return -1;
        }
      }
      return 0;
    }
  } else if ( strncasecmp(nms, "sec-websocket-key", nme - nms) == 0 ) {
    static const char ws_magic[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    SHA_CTX ctx;
    unsigned char digest_out[SHA_DIGEST_LENGTH];
    size_t key_out_sz = sizeof(hs->ws_accept_key);

    if ( !SHA1_Init(&ctx) ) {
      hs->ws_error = 500;
      return -1;
    }

    if ( !SHA1_Update(&ctx, (const void *) vls, vle - vls) ) {
      hs->ws_error = 500;
      return -1;
    }

    if ( !SHA1_Update(&ctx, (const void *) ws_magic, strlen(ws_magic)) ) {
      hs->ws_error = 500;
      return -1;
    }

    if ( !SHA1_Final(digest_out, &ctx) ) {
      hs->ws_error = 500;
      return -1;
    }

    hs->ws_accept_key_len = sizeof(hs->ws_accept_key);
    if ( b64_encode(digest_out, sizeof(digest_out),
                    hs->ws_accept_key, &key_out_sz) != 0 ) {
      hs->ws_error = 500;
      return -1;
    }

    hs->ws_flags |= WS_HAS_ACCEPT_KEY;
    hs->ws_accept_key_len = key_out_sz;

    return 0;
  } else {
#if 0
    fprintf(stderr, "parse_http_header: unknown header %.*s: %.*s\n", (int) (nme - nms), nms,
            (int) (vle - vls), vls);
#endif
    return 0;
  }
}

static int parse_ws_handshake(struct wsconnection *wsc, struct wshs *hs, int *req_end) {
  char *buf = wsc->wsc_pkt_buf;
  int bytes_left = wsc->wsc_pkt_sz;

  int ps_state = HTTP_PS_VERB, err;

  const char *method_start, *method_end;
  const char *hdrnm_start, *hdrnm_end;
  const char *version_start, *version_end;
  const char *hdrval_start, *hdrval_end;

  *req_end = 0;

  method_start = buf;
  version_start = method_end = NULL;

  hs->ws_flags = 0;
  hs->ws_version = 0;
  hs->ws_loc_start = hs->ws_loc_end = NULL;
  hs->ws_error = 101;

  while ( bytes_left > 0 ) {
    switch ( ps_state ) {
    case HTTP_PS_VERSION:
      if ( *buf == '\r' ) {
        version_end = buf;
        if ( strncmp(version_start, "HTTP/1.1", version_end - version_start) != 0 ) {
          hs->ws_error = 505;
          return -1;
        }
        HTTP_CONSUME_NEWLINE;
        ps_state = HTTP_PS_HEADER_OR_END;
        continue;
      }
    case HTTP_PS_VERB:
    case HTTP_PS_LOCATION:
      if ( *buf == ' ' ) {
        switch ( ps_state ) {
        case HTTP_PS_VERB:
          method_end = buf;
          HTTP_SKIP_SPACE;
          if ( strncmp(method_start, "GET", method_end-method_start) != 0 ) {
            hs->ws_error = 405;
            return -1;
          }
          ps_state = HTTP_PS_LOCATION;
          hs->ws_loc_start = buf;
          break;
        case HTTP_PS_LOCATION:
          hs->ws_loc_end = buf;
          HTTP_SKIP_SPACE;
          ps_state = HTTP_PS_VERSION;
          version_start = buf;
          break;
        case HTTP_PS_VERSION:
	  fprintf(stderr, "parse_ws_handshake: trailing junk after HTTP version\n");
          hs->ws_error = 400;
          return -1;
        default:
          hs->ws_error = 500;
          return -1;
        }
      } else {
        HTTP_NEXT_CHAR;
      }
      break;
    case HTTP_PS_HEADER_OR_END:
      if ( *buf == '\r' || *buf == '\n' ) {
        HTTP_CONSUME_NEWLINE;
        ps_state = HTTP_PS_END;
      } else {
        // Otherwise, this is a header name
        hdrnm_start = buf;
        hdrnm_end = NULL;
        ps_state = HTTP_PS_HEADER_NAME;
      }
      break;
    case HTTP_PS_HEADER_NAME:
      if ( *buf == ':' ) {
        hdrnm_end = buf;
        if ( hdrnm_end == hdrnm_start ) {
	  fprintf(stderr, "parse_ws_handshake: empty header name\n");
          hs->ws_error = 400;
          return -1;
        }
        ps_state = HTTP_PS_HEADER_COLON;
        HTTP_NEXT_CHAR;
      } else {
        HTTP_NEXT_CHAR;
      }
      break;
    case HTTP_PS_HEADER_COLON:
      if ( *buf == ' ' ) {
        ps_state = HTTP_PS_HEADER_VALUE;
        HTTP_NEXT_CHAR;
        hdrval_start = buf;
        hdrval_end = NULL;
      } else {
	fprintf(stderr, "parse_ws_handshake: no space after colon\n");
        hs->ws_error = 400;
        return -1;
      }
      break;
    case HTTP_PS_HEADER_VALUE:
      if ( *buf == '\r' ) {
        hdrval_end = buf;
        HTTP_CONSUME_NEWLINE;

        err = parse_http_header(hs, hdrnm_start, hdrnm_end,
                                hdrval_start, hdrval_end);
        if ( err < 0 ) return err;

        ps_state = HTTP_PS_HEADER_OR_END;
      } else {
        HTTP_NEXT_CHAR;
      }
      break;
    case HTTP_PS_END:
      fprintf(stderr, "Trailing junk at end of HTTP request\n");
      hs->ws_error = 400;
      return -1;
    default:
      abort();
    }
  }

  if ( ps_state == HTTP_PS_END &&
       hs->ws_flags & (WS_HAS_CONNECTION_UPGRADE | WS_HAS_UPGRADE_WEBSOCKET | WS_HAS_ACCEPT_KEY) ) {
    *req_end = wsc->wsc_pkt_sz - bytes_left;
    return 0;
  }

  return 1; // Wait for more
}

static void send_handshake_response(struct wsconnection *wsc, struct wshs *hs) {
  struct eventloop *el = wsc->wsc_conn.conn_el;
  char accept_header[128];
  int err;

  err = snprintf(accept_header, sizeof(accept_header), "Sec-WebSocket-Accept: %.*s",
                 hs->ws_accept_key_len, hs->ws_accept_key);
  assert(err < sizeof(accept_header));
  (void)err; // Prevent unused variable in release mode

  wsconnection_respond_line(wsc, el, "HTTP/1.1 101 Switching Protocols");
  wsconnection_respond_line(wsc, el, "Upgrade: websocket");
  wsconnection_respond_line(wsc, el, "Connection: Upgrade");
  wsconnection_respond_line(wsc, el, accept_header);
  wsconnection_respond_line(wsc, el, "");

  WSC_SUBSCRIBE_WRITE(wsc);
}

static void send_http_error(struct wsconnection *wsc, struct wshs *hs) {
  struct eventloop *el = wsc->wsc_conn.conn_el;

  switch ( hs->ws_error ) {
  case 400:
    wsconnection_respond_line(wsc, el, "HTTP/1.1 400 Bad Request");
    break;
  case 405:
    wsconnection_respond_line(wsc, el, "HTTP/1.1 405 Bad Method");
    wsconnection_respond_line(wsc, el, "HTTP/1.1 Allow: GET");
    break;
  case 505:
    wsconnection_respond_line(wsc, el, "HTTP/1.1 505 HTTP Version Not Supported");
    break;
  default:
  case 500:
    wsconnection_respond_line(wsc, el, "HTTP/1.1 500 Internal Server Error");
    break;
  }

  wsconnection_respond_line(wsc, el, "");

  WSC_SUBSCRIBE_WRITE(wsc);
}

static int wsconnection_nl_mode(struct wsconnection *wsc, const char *buf, int *sz) {
  int i;

  for ( i = 0; i < *sz; ++i ) {
    switch ( buf[i] ) {
    case '\r':
      switch ( wsc->wsc_nl_mode ) {
      case WSC_NL_NONE:
      case WSC_NL_CR1:
      case WSC_NL_CR2:
        wsc->wsc_nl_mode = WSC_NL_CR1;
        break;
      case WSC_NL_NL1:
        wsc->wsc_nl_mode = WSC_NL_CR2;
        break;
      default: abort();
      }
      break;

    case '\n':
      switch ( wsc->wsc_nl_mode ) {
      case WSC_NL_NONE:
      case WSC_NL_CR1:
        wsc->wsc_nl_mode = WSC_NL_NL1;
        break;
      case WSC_NL_NL1:
      case WSC_NL_CR2:
        *sz = i;
        return 1;
      default: abort();
      }
      break;

    default:
      wsc->wsc_nl_mode = WSC_NL_NONE;
    }
  }

  return 0;
}
