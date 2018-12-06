#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <storkd_proto.h>

#define SCTP_DEBUG 1
//#include <usrsctp.h>
#include <netinet/sctp.h>

#include "webrtc.h"
#include "util.h"

#ifndef SCTP_INTERLEAVING_SUPPORTED
#define SCTP_INTERLEAVING_SUPPORTED 125
#endif

#ifndef WEBRTC_PROXY_DEBUG
#define WEBRTC_PROXY_DEBUG 0
#endif

#define COMM 3

#if WEBRTC_PROXY_DEBUG
#define log_printf(...) fprintf(stderr, __VA_ARGS__)
#else
#define log_printf(...) (void) 0;
#endif

#define SCTP_OUTBOUND_STREAMS 2048

#define WEBRTC_NAME_MAX 128
#define APP_ID_MAX      512

#define PACKED          __attribute__((packed))

struct stack_ent {
  struct stack_ent *next;
};

#define STACK_END_MARKER ((void *) (~((uintptr_t) 0)))
#define STACK_INIT { NULL }
#define STACK_IS_EMPTY(stack_ent) ((stack_ent)->next == NULL)
#define CLEAR_STACK(stack_ent) (void) ((stack_ent)->next = NULL)
#define PUSH_STACK(stack_ent, new_top, field)                           \
  if ((new_top)->field.next == NULL) {                                  \
    (new_top)->field.next = (stack_ent)->next;                          \
    if ( (new_top)->field.next == 0 )                                   \
      (new_top)->field.next = (void *)~0;                               \
    (stack_ent)->next = &((new_top)->field);                            \
  }
#define GET_STACK(stack_ent, result_ty, field) ((result_ty *) (((stack_ent)->next && (stack_ent)->next != STACK_END_MARKER) ? (((uintptr_t) (stack_ent)->next) - offsetof(result_ty, field)) : 0))
#define CONSUME_STACK(stack_head, v, result_ty, field)                  \
  for ( v = GET_STACK(stack_head, result_ty, field); v;                 \
        (stack_head)->next = v->field.next == STACK_END_MARKER ? 0 : v->field.next, \
        v->field.next = NULL,                                           \
        v = GET_STACK(stack_head, result_ty, field) )
#define READ_STACK(stack_head, v, result_ty, field)     \
  for ( v = GET_STACK(stack_head, result_ty, field); v; v = GET_STACK(&(v)->field, result_ty, field) )
#define FREE_STACK(stack_head, result_ty, field, do_free)               \
  do {                                                                  \
    result_ty *__tmp_ ## __LINE__, *__cur_ ## __LINE__;                 \
    for ( __cur_ ## __LINE__ = GET_STACK(stack_head, result_ty, field), \
            __tmp_ ## __LINE__ = (__cur_ ## __LINE__ ?                  \
                                  GET_STACK(&(__cur_ ## __LINE__ ->field), \
                                            result_ty, field) : NULL ); \
          __cur_ ## __LINE__;                                           \
          __cur_ ## __LINE__ ->field.next = NULL,                       \
          __cur_ ## __LINE__ = __tmp_ ## __LINE__,                      \
            __tmp_ ## __LINE__ = (__tmp_ ## __LINE__ ?                  \
                                  GET_STACK(&(__tmp_ ## __LINE__ ->field), \
                                            result_ty, field) : NULL ) ) \
      do_free(__cur_ ## __LINE__);                                      \
  } while (0)

//#define CONTROL_PROTO_NAME "control"
//#define CONTROL_PROTO_LEN  7
#define PROXY_BUF_SIZE  1024

typedef uint16_t wrcchanid;
struct wrtcchan {
  uint8_t  wrc_sts;
  wrcchanid wrc_chan_id;

  char     wrc_label[WEBRTC_NAME_MAX];
  char     wrc_proto[WEBRTC_NAME_MAX];

  uint8_t  wrc_ctype;
  uint16_t wrc_prio;
  uint32_t wrc_rel;

  int      wrc_family;
  int      wrc_type;

  int      wrc_sk;

  // Messages we have received externally that have yet to be written locally
  char    *wrc_buffer;
  size_t   wrc_buf_sz, wrc_msg_sz;

  // If the WRC_RETRY_MSG flag is set, this is the amount of retries
  // left before giving up
  int      wrc_retries_left;
  int      wrc_retry_interval_millis;

  uint8_t  wrc_retry_rsp;

  struct timespec wrc_last_msg_sent, wrc_created_at;

  uint32_t wrc_flags;

  // Stuff we've received locally but haven't written out over SCTP
  int wrc_proxy_buf_sz;
  char wrc_proxy_buf[PROXY_BUF_SIZE];

  struct stack_ent wrc_closed_stack;
  struct stack_ent wrc_pending_reads;
  struct stack_ent wrc_reset_stack;
};

#define WRC_HAS_MESSAGE_PENDING(chan)                                   \
  (((chan)->wrc_flags & WRC_HAS_OUTGOING) ||                            \
   (((chan)->wrc_flags & WRC_RETRY_MSG) && (chan)->wrc_retries_left > 0))
#define WRC_IS_CONTROL(chan) ((chan)->wrc_flags & WRC_CONTROL)

#define WEBRTC_STS_INVALID   0
#define WEBRTC_STS_VALID     1
#define WEBRTC_STS_OPEN      2
#define WEBRTC_STS_CONNECTED 3

//Bitmasks for wrc_flags
#define WRC_CONTROL          0x01
#define WRC_HAS_OUTGOING     0x02
#define WRC_RETRY_MSG        0x04
#define WRC_ERROR_ON_RETRY   0x08
#define WRC_HAS_PENDING_CONN 0x10
#define WRC_READ_CLOSED      0x20
#define WRC_DATA_IN_PROG     0x40 // We have not finished writing the data in progress
#define WRC_WAIT_FOR_SCTP_OUT 0x80
#define WRC_WRITE_CLOSED     0x100
#define WRC_NEEDS_CONN_OPENS_RSP 0x200
#define WRC_SCM_IN_PROG      0x400
#define WRC_NEEDS_CONNECT    0x800

#define WEBRTC_CHANID(sid) (sid)
#define WEBRTC_CLIENT_SID(chan_id) (chan_id)
#define WEBRTC_SERVER_SID(chan_id) (chan_id)

// pending connection
struct wrcpendingconn {
  struct sockaddr_in wpc_sin;
};

// Messages that we receive on a control or data socket
struct stkcmsg {
  uint8_t scm_type;
  union {
    struct {
      uint32_t scm_app_len;
      char scm_app_id[];
    } PACKED scm_open_app_request;
    struct {
      uint8_t scm_retries;
      uint8_t scm_sk_type;
      uint16_t scm_port;
      uint32_t scm_app;
    } PACKED scm_connect;
    uint32_t scm_opened_app;
    uint32_t scm_error;
    struct {
      uint32_t scm_flags; // Data Flags (reserved for now)
      char scm_bod; // Beginning of data. Use with & to get address of first character
    } PACKED scm_data;
  } data;
} PACKED;

#define STK_CMSG_REQ(msg) ((msg)->scm_type & SCM_REQ_MASK)
#define STK_CMSG_IS_RSP(msg) ((msg)->scm_type & SCM_RESPONSE)
#define SCM_DATA(req) ((void *) &(req)->data.scm_data.scm_bod)

#define SCM_RESPONSE     0x80 // bitmask for responses to requests
#define SCM_ERROR        0x40 // bitmask for responses that are errors
#define SCM_REQ_MASK     0x0F

#define SCM_REQ_OPEN_APP 0x1
#define SCM_REQ_CONNECT  0x2
#define SCM_REQ_DATA     0xF

#define SCM_OPEN_APP_REQ_SZ_MIN 5
#define SCM_OPENED_APP_RSP_SZ   5
#define SCM_ERROR_RSP_SZ        5
#define SCM_CONNECT_REQ_SZ      9
#define SCM_CONNECT_RSP_SZ      1
#define SCM_DATA_REQ_SZ         5

#define STORKD_ADDR "10.0.0.2"
#define STORKD_OPEN_APP_PORT 9998 // The port where we send open app requests

#define OUTGOING_BUF_SIZE    65536
#define PACKET_BUF_SIZE      65536
#define OPEN_APP_MAX_RETRIES 7
#define MAX_EPOLL_EVENTS     16
#define ADDR_DESC_TBL_SZ     1024
#define DFL_EPOLL_EVENTS     (EPOLLIN | EPOLLRDHUP | EPOLLPRI | EPOLLONESHOT)

// Global state

#define SCTP_FUTURE_ASSOC    0

const char *g_capability = NULL;

sctp_assoc_t g_webrtc_assoc = SCTP_FUTURE_ASSOC;
int g_max_strms = 1024;
int g_num_strms = 1024;

int g_dbg_port = -1;

struct wrtcchan *g_channels = NULL;
struct wrtcchan **g_channel_htbl = NULL;
struct stack_ent g_pending_free_channels = STACK_INIT;
int g_channels_open = 0;

wrcchanid *g_closing_chans = NULL;
int g_closing_chans_pending = 0;

uint32_t g_address_table[ADDR_DESC_TBL_SZ];
int g_address_next_desc = 0;

int g_epollfd;

struct stack_ent g_pending_reads = STACK_INIT;
struct stack_ent g_reset_in_progress = STACK_INIT;
int g_reset_retries = 0;

static int receive_sctp(int srv);

// Utilities

void millis_to_timespec(struct timespec *ts, int millis) {
  ts->tv_sec = millis / 1000;
  ts->tv_nsec = (millis % 1000) * 1000000;
}

void timespec_add(struct timespec *r, struct timespec *o1, struct timespec *o2) {
  long unsigned int nsecs = o1->tv_nsec + o2->tv_nsec;
  r->tv_sec = o1->tv_sec + o2->tv_sec + (nsecs / 1000000000);
  r->tv_nsec = nsecs % 1000000000;
}

int timespec_lt(struct timespec *a, struct timespec *b) {
  if ( a->tv_sec < b->tv_sec ) return 1;
  else if ( a->tv_sec > b->tv_sec ) return 0;
  else {
    return a->tv_nsec < b->tv_nsec;
  }
}

uint32_t translate_stk_connection_error(int which) {
  uint32_t ret;
  switch ( which ) {
  case ENOENT:       ret = STKD_ERROR_INVALID_ADDR; break;
  case ENETUNREACH:
  case ECONNREFUSED: ret = STKD_ERROR_CONN_REFUSED; break;
  case EALREADY:     ret = STKD_ERROR_SYSTEM_BUSY; break;
  case ETIMEDOUT:    ret = STKD_ERROR_TEMP_UNAVAILABLE; break;
  default:           ret = STKD_ERROR_SYSTEM_ERROR; break;
  }

  return ret;
}

int mk_socket(int sk_type) {
  int err;

  err = socket(AF_INET, sk_type | SOCK_NONBLOCK, 0);
  if ( err < 0 ) {
    perror("mk_socket: socket");
    return -1;
  }

  return err;
}

// Attempt to connect the socket. Returns 0 on success, 1 if the
// connection is in progress, and -1 on error
int connect_socket(struct wrtcchan *chan, struct sockaddr_in *sin) {
#if WEBRTC_PROXY_DEBUG
  char name[INET6_ADDRSTRLEN];
#endif
  int err;

  if ( clock_gettime(CLOCK_REALTIME, &chan->wrc_last_msg_sent) < 0 ) {
    perror("connect_socket: clock_gettime");
  }

  log_printf("Will connect to %s:%d\n",
             inet_ntop(AF_INET, &sin->sin_addr, name, sizeof(name)),
             ntohs(sin->sin_port));
  err = connect(chan->wrc_sk, (struct sockaddr *) sin, sizeof(*sin));
  if ( err < 0 ) {
    if ( errno == EINPROGRESS ) {
      log_printf("The connection has been queued and is in progress\n");
      return 1;
    } else {
      int saved_errno = errno;
      perror("connect_socket: connect");
      errno = saved_errno;
      close(chan->wrc_sk);
      chan->wrc_sk = 0;
      return -1;
    }
  } else
    log_printf("Connected on first attempt!\n");

  return 0;
}

// address utilities
int get_address_descriptor(uint32_t ip) {
  int i = 0, ret = -1;

  for ( i = 0; i < g_address_next_desc; ++i ) {
    if ( g_address_table[i] == ip ) {
      ret = i;
      goto done;
    }
  }

  if ( g_address_next_desc >= ADDR_DESC_TBL_SZ )
    return -1;

  ret = g_address_next_desc++;
  g_address_table[i] = ip;

 done:
  return ret;
}

int get_address_by_descriptor(int desc, uint32_t *ip) {
  int ret;

  if ( desc < g_address_next_desc ) {
    ret = 1;
    *ip = g_address_table[desc];
  } else
    ret = 0;

  return ret;
}

// channel utilities

inline uint8_t get_chan_sts(struct wrtcchan *c) {
  return __atomic_load_n(&c->wrc_sts, __ATOMIC_CONSUME);
}

inline void set_chan_sts(struct wrtcchan *c, uint8_t newsts) {
  __atomic_store_n(&c->wrc_sts, newsts, __ATOMIC_SEQ_CST);
}

int chan_has_more_proxying(struct wrtcchan *c) {
  int bytes_left = 0;

  ioctl(c->wrc_sk, SIOCINQ, &bytes_left);

  return bytes_left || (c->wrc_flags & WRC_HAS_OUTGOING);
}

void insert_chan_in_htbl(struct wrtcchan *c) {
  int hidx = c->wrc_chan_id % g_num_strms;
  for ( ; g_channel_htbl[hidx]; hidx ++ );
  g_channel_htbl[hidx] = c;
}

struct wrtcchan *find_chan(wrcchanid cid) {
  int hidx, first_idx, scan_count;
  struct wrtcchan *ret;

  first_idx = cid % g_num_strms;
  scan_count = 0;
  for ( hidx = first_idx;
        g_channel_htbl[hidx] && g_channel_htbl[hidx]->wrc_chan_id != cid;
        ++ hidx ) {
    if ( hidx == first_idx ) scan_count ++;
    if ( scan_count > 1 ) break;
  }

  if ( scan_count > 1 ) ret = NULL;
  else ret = g_channel_htbl[hidx];

  return ret;
}

void remove_chan_from_tbl(struct wrtcchan *c) {
  int hidx = c->wrc_chan_id % g_num_strms, jidx, kidx = 0;

  // TODO test this
  if ( g_channel_htbl[hidx] ) {
    jidx = hidx;

    while ( 1 ) {
      g_channel_htbl[hidx] = NULL;

      do {
        jidx = (jidx + 1) % g_num_strms;
        log_printf("remove_chan_from_tbl: hidx=%d jidx=%d kidx=%d; %p\n", hidx, jidx, kidx, g_channel_htbl[jidx]);

        if ( !g_channel_htbl[jidx] ) return;

        kidx = g_channel_htbl[jidx]->wrc_chan_id % g_num_strms;
      } while ( (hidx <= jidx) ?
                ((hidx < kidx) && (kidx <= jidx)) :
                ((hidx < jidx) || (kidx <= jidx)) );

      g_channel_htbl[hidx] = g_channel_htbl[jidx];

      hidx = jidx;
    }
  }
}

// Allocates a new channel and returns it in a locked state
struct wrtcchan *alloc_wrtc_chan(wrcchanid chan_id) {
  int i = 0;
  struct wrtcchan *ret = NULL;

  for ( i = 0; i < g_num_strms; ++i ) {
    if ( get_chan_sts(&g_channels[i]) == WEBRTC_STS_INVALID ) {
      g_channels[i].wrc_sts = WEBRTC_STS_VALID;
      g_channels[i].wrc_chan_id = chan_id;
      memset(&g_channels[i].wrc_label, 0, WEBRTC_NAME_MAX);
      memset(&g_channels[i].wrc_proto, 0, WEBRTC_NAME_MAX);
      g_channels[i].wrc_family = 0;
      g_channels[i].wrc_type = 0;
      g_channels[i].wrc_sk = 0;
      g_channels[i].wrc_ctype = 0xFF;

      CLEAR_STACK(&(g_channels[i].wrc_closed_stack));
      CLEAR_STACK(&(g_channels[i].wrc_reset_stack));
      CLEAR_STACK(&(g_channels[i].wrc_pending_reads));

      insert_chan_in_htbl(&g_channels[i]);

      ret = &g_channels[i];
      goto done;
    }
  }

 done:
  return ret;
}

void dealloc_wrtc_chan(struct wrtcchan *chan) {
  remove_chan_from_tbl(chan);

  chan->wrc_sts = WEBRTC_STS_INVALID;

  if ( chan->wrc_sk ) {
    close(chan->wrc_sk);
    //fprintf(stderr, "dealloc_wrtc_chan: closing sk %d\n", chan->wrc_sk);
  }

  if ( chan->wrc_buffer ) {
    free(chan->wrc_buffer);
    chan->wrc_buffer = NULL;
  }
}

void mark_channel_closed(struct wrtcchan *chan) {
  chan->wrc_flags |= WRC_WRITE_CLOSED;
  //  fprintf(stderr, "mark_channel_closed: chnnel %d\n", chan->wrc_chan_id);
  PUSH_STACK(&g_pending_free_channels, chan, wrc_closed_stack);
}

void force_close_channel(struct wrtcchan *chan) {
  if ( chan->wrc_sk > 0 ) {
    close(chan->wrc_sk);
    chan->wrc_sk = -1;
  }
}

void rsp_cmsg_error(int srv, struct wrtcchan *chan, uint8_t req, int rsperr) {
  struct stkcmsg msg;
  struct sctp_sndrcvinfo sri;
  int err;

  log_printf("CMSG error: %d %d\n", chan->wrc_chan_id, rsperr);

  msg.scm_type = req | SCM_RESPONSE | SCM_ERROR;
  msg.data.scm_error = htonl(rsperr);

  memset(&sri, 0, sizeof(sri));
  sri.sinfo_stream = WEBRTC_SERVER_SID(chan->wrc_chan_id);
  sri.sinfo_ppid = htonl(WEBRTC_BINARY_PPID);
  sri.sinfo_context = chan->wrc_chan_id;
  sri.sinfo_assoc_id = g_webrtc_assoc;

  err = sctp_send(srv, (void *) &msg, sizeof(msg), &sri, 0);
  if ( err < 0 ) {
    perror("send_cmsg_error: sctp_send");
    // TODO close the channel or something
  }
}

// void reset_wrc_chan(int srv, wrcchanid chan_id) {
//   int i, open_ix = -1;
//
//   for ( i = 0; i < g_num_strms; ++i ) {
//     if ( g_closing_chans[i] == 0xFFFF ) {
//       if ( open_ix == -1 )
//         open_ix = i;
//     } else if ( g_closing_chans[i] == chan_id ) {
//       open_ix = -2;
//       break;
//     }
//   }
//   if ( open_ix == -1 ) {
//     fprintf(stderr, "WARNING: ran out of space in closing chans?\n");
//   } else if ( open_ix >= 0 ) {
//     g_closing_chans_pending++;
//     g_closing_chans[open_ix] = chan_id;
//   }
//   fprintf(stderr, "Marked %d for delayed close\n", chan_id);
// }

void do_not_close_channel(wrcchanid chan) {
  int i = 0;

  for ( i = 0; i < g_num_strms; ++i ) {
    if ( g_closing_chans[i] == chan ) {
      g_closing_chans[i] = 0xFFFF;
      g_closing_chans_pending --;
    }
  }
}

//void perform_delayed_resets(int srv) {
//
//  if ( g_closing_chans_pending ) {
//    struct sctp_reset_streams *srs;
//    int i, chan_ix;
//    size_t buf_sz = sizeof(struct sctp_reset_streams) + sizeof(uint16_t) * g_closing_chans_pending;
//    srs = malloc(buf_sz);
//    assert(srs);
//
//    srs->srs_assoc_id = g_webrtc_assoc;
//    srs->srs_flags = SCTP_STREAM_RESET_OUTGOING;
//    srs->srs_number_streams = g_closing_chans_pending;
//
//    for ( i = 0, chan_ix = 0; i < g_num_strms; ++i ) {
//      if ( g_closing_chans[i] != 0xFFFF ) {
//        //        fprintf(stderr, "reset %d\n", g_closing_chans[i]);
//        srs->srs_stream_list[chan_ix] = g_closing_chans[i];
//        chan_ix ++;
//      }
//    }
//
//    assert(chan_ix == g_closing_chans_pending);
//
//    if ( setsockopt(srv, IPPROTO_SCTP, SCTP_RESET_STREAMS, srs, buf_sz) < 0 &&
//         errno != EINPROGRESS ) {
//      perror("sctp_setsockopt SCTP_RESET_STREAMS");
//      if ( errno == EAGAIN ) {
//        fprintf(stderr, "perform_delayed_resets: trying again later\n");
//      }
//    } else {
//      fprintf(stderr, "perform_delayed_resets: success\n");
//
//      g_closing_chans_pending = 0;
//      memset(g_closing_chans, 0xFF, g_num_strms * sizeof(*g_closing_chans));
//    }
//    free(srs);
//  }
//}

// Returns 0 if the close was performed. 1 if we need write ability on the socket
void perform_delayed_closes(int srv) {
  struct wrtcchan *chan;

  if ( STACK_IS_EMPTY(&g_reset_in_progress) && !STACK_IS_EMPTY(&g_pending_free_channels) ) {
    int total_cnt = 0, i = 0;

    CONSUME_STACK(&g_pending_free_channels, chan, struct wrtcchan, wrc_closed_stack) {
      // log_printf("Closing channel %d (delayed)\n", chan->wrc_chan_id);
      fprintf(stderr, "Closing channel %d (delayed) %p\n", chan->wrc_chan_id, g_reset_in_progress.next);
      PUSH_STACK(&g_reset_in_progress, chan, wrc_reset_stack);
      total_cnt++;
    }

    if ( total_cnt > 0 ) {
      int buf_sz = sizeof(struct sctp_reset_streams) + sizeof(uint16_t) * total_cnt;
      struct sctp_reset_streams *srs = malloc(buf_sz);
      if ( !srs ) {
        fprintf(stderr, "webrtc-proxy: out of memory\n");
        abort();
      }

      srs->srs_assoc_id = g_webrtc_assoc;
      srs->srs_flags = SCTP_STREAM_RESET_OUTGOING;
      srs->srs_number_streams = total_cnt;

      READ_STACK(&g_reset_in_progress, chan, struct wrtcchan, wrc_reset_stack) {
        fprintf(stderr, "Marking %d (sk %d) for deletion (i = %d, srs->stream_list=%p, sz=%d)\n", chan->wrc_chan_id, chan->wrc_sk, i, srs->srs_stream_list, buf_sz);
        srs->srs_stream_list[i] = chan->wrc_chan_id;
        i++;
      }

      if ( setsockopt(srv, IPPROTO_SCTP, SCTP_RESET_STREAMS, srs, buf_sz) < 0 &&
           errno != EINPROGRESS ) {
        if ( errno == EAGAIN ) {
          sched_yield();
          //fprintf(stderr, "perform_delayed_closes: trying again later\n");

          // Put everything back
          CONSUME_STACK(&g_reset_in_progress, chan, struct wrtcchan, wrc_reset_stack) {
            PUSH_STACK(&g_pending_free_channels, chan, wrc_closed_stack);
          }
        } else
          perror("sctp_setsockopt SCTP_RESET_STREAMS");
      } else {
        log_printf( "Successfully requested stream reset\n");
      }

      free(srs);
    };
  }

  //  log_printf("We have now closed all delayed channels\n");
}

void process_strreset_ack(struct sctp_stream_reset_event *rse, int sz) {
  int stream_list_sz = sz - sizeof(*rse);
  int stream_cnt = stream_list_sz / sizeof(rse->strreset_stream_list[0]);
  int i;
  struct wrtcchan *chan;
  struct stack_ent to_free = STACK_INIT, still_resetting = STACK_INIT;

  if ( sz != rse->strreset_length )
    fprintf(stderr, "process_strreset_ack: warning: length mismatch between header and recv()\n");

  if ( rse->strreset_assoc_id != g_webrtc_assoc ) {
    fprintf(stderr, "process_strreset_ack: received reset event for an unknown association\n");
    return;
  }

  log_printf("process_strreset_ack: got stream reset\n");

  log_printf("process_strreset_ack: received stream reset ack for %d channels: %08x\n",
             stream_cnt, rse->strreset_flags);

  if ( rse->strreset_flags & SCTP_STREAM_RESET_DENIED ) {
    fprintf(stderr, "process_strreset_ack: WARNING: reset denied. This is almost certainly an error in the remote WebRTC implementation\n");
    abort();
  }

  if ( rse->strreset_flags & SCTP_STREAM_RESET_FAILED ) {
    fprintf(stderr, "process_strreset_ack: stream reset failed. Retrying\n");
    if ( g_reset_retries > 7 ) {
      fprintf(stderr, "process_strreset_ack: no more retries left. Aborting\n");
      abort();
    } else {
      g_reset_retries++;

      // Move everything back to pending_free
      CONSUME_STACK(&g_reset_in_progress, chan, struct wrtcchan, wrc_reset_stack) {
        PUSH_STACK(&g_pending_free_channels, chan, wrc_closed_stack);
      }
    }

    return;
  }

  // Successful resets
  g_reset_retries = 0;

  CONSUME_STACK(&g_reset_in_progress, chan, struct wrtcchan, wrc_reset_stack) {
    int channel_was_reset = 0;

    for ( i = 0; i < stream_cnt; ++i ) {
      if ( WEBRTC_CHANID(rse->strreset_stream_list[i]) == chan->wrc_chan_id ) {
        log_printf( "process_strreset_ack: received ack for %d\n", chan->wrc_chan_id);
        channel_was_reset = 1;
        rse->strreset_stream_list[i] = 0xFFFF;
        break;
      }
    }

    if ( channel_was_reset ) {
      // This channel was reset
      PUSH_STACK(&to_free, chan, wrc_closed_stack);
    } else {
      PUSH_STACK(&still_resetting, chan, wrc_closed_stack);
    }
  }

  CONSUME_STACK(&still_resetting, chan, struct wrtcchan, wrc_closed_stack) {
    PUSH_STACK(&g_reset_in_progress, chan, wrc_reset_stack);
  }

  for ( i = 0; i < stream_cnt; ++i ) {
    if ( rse->strreset_stream_list[i] != 0xFFFF ) {
      chan = find_chan(WEBRTC_CHANID(rse->strreset_stream_list[i]));
      if ( !chan ) {
        fprintf(stderr, "process_strreset_ack: received new stream reset for unopened channel %d\n",
                rse->strreset_stream_list[i]);
      } else {
        fprintf(stderr, "process_strreset_ack: received new stream reset for %d\n", rse->strreset_stream_list[i]);
        force_close_channel(chan);
        mark_channel_closed(chan);
      }
    }
  }

  //fprintf(stderr, "Freeing stack responded to\n");
  FREE_STACK(&to_free, struct wrtcchan, wrc_closed_stack, dealloc_wrtc_chan);
  //fprintf(stderr, "Done freeing responded to stream resets\n");
}

void wait_for_write_on_chan(struct wrtcchan *chan) {
  struct epoll_event ev;
  int err;

  ev.events = DFL_EPOLL_EVENTS | EPOLLOUT;
  ev.data.ptr = (void *) chan;

  if ( chan->wrc_flags & WRC_WAIT_FOR_SCTP_OUT ) // Ignore HAS_OUTGOING because this is called to initiate a connect
    ev.events &= ~EPOLLIN;

  err = epoll_ctl(g_epollfd, EPOLL_CTL_MOD, chan->wrc_sk, &ev);
  if ( err == -1 ) {
    perror("epoll_ctl EPOLL_CTL_MOD write");
  }
}

void mark_channel_writable(struct wrtcchan *chan, int retries_left, int retry_millis) {
  log_printf("WebRTC: signalling write on channel %d\n", chan->wrc_chan_id);
  chan->wrc_flags |= WRC_HAS_OUTGOING;
  if ( retries_left > 0 && retry_millis > 0 ) {
    chan->wrc_flags |= WRC_RETRY_MSG;
    chan->wrc_retries_left = retries_left;
    chan->wrc_retry_interval_millis = (retry_millis > 2) ? (retry_millis / 2) : 1;
  }
}

void signal_write_on_chan(struct wrtcchan *chan, int retries_left, int retry_millis) {
  mark_channel_writable(chan, retries_left, retry_millis);
  wait_for_write_on_chan(chan);
}

void signal_new_timeout() {
//  int err = pthread_kill(g_epoll_thread, SIGUSR1);
//  if ( err != 0 ) {
//    errno = err;
//    perror("pthread_kill SIGUSR1");
//  }
//
//  log_printf("Signaled timeout\n");
}

void disarm_channel(struct wrtcchan *chan) {
  struct epoll_event ev; // Must be supplied in some kernels
  int err = epoll_ctl(g_epollfd, EPOLL_CTL_DEL, chan->wrc_sk, &ev);
  if ( err < 0 ) {
    perror("epoll_ctl EPOLL_CTL_DEL");
  }
}

void arm_channel(struct wrtcchan *chan) {
  struct epoll_event ev;
  int err;

  ev.events = DFL_EPOLL_EVENTS;
  ev.data.ptr = (void *) chan;

  if ( chan->wrc_flags & WRC_HAS_OUTGOING )
    ev.events |= EPOLLOUT;

  log_printf("Arming channel %d (fd %d) with %d\n", chan->wrc_chan_id, chan->wrc_sk, ev.events);

  err = epoll_ctl(g_epollfd, EPOLL_CTL_ADD, chan->wrc_sk, &ev);
  if ( err < 0 ) {
    perror("arm_channel: epoll_ctl EPOLL_CTL_ADD");
  }
}

void arm_sctp(int srv) {
  struct epoll_event ev;
  int err;

  ev.events = DFL_EPOLL_EVENTS;
  ev.data.ptr = NULL;

  err = epoll_ctl(g_epollfd, EPOLL_CTL_ADD, srv, &ev);
  if ( err < 0 ) {
    perror("arm_sctp: epoll_ctl EPOLL_CTL_ADD");
  }
}

// Marks the channel as open (meaning it is currently connecting)
void mark_channel_connecting(struct wrtcchan *chan,
                             struct sockaddr_in *in,
                             int retries) {
  struct wrcpendingconn *pconn = (struct wrcpendingconn *) chan->wrc_buffer;

  // Close the control socket, and unset the flag
  chan->wrc_sts = WEBRTC_STS_OPEN; // The open status signifies that we are connecting
  chan->wrc_flags &= ~(WRC_CONTROL | WRC_SCM_IN_PROG);
  chan->wrc_flags |= WRC_HAS_PENDING_CONN | WRC_RETRY_MSG;
  chan->wrc_msg_sz = sizeof(*pconn);
  chan->wrc_retries_left = retries;
  chan->wrc_retry_interval_millis = 200;

  memcpy(&pconn->wpc_sin, in, sizeof(pconn->wpc_sin));

  arm_channel(chan);
  wait_for_write_on_chan(chan);
}

void mark_channel_connected(struct wrtcchan *chan) {
  chan->wrc_sts = WEBRTC_STS_CONNECTED;
  chan->wrc_flags &= ~(WRC_CONTROL | WRC_HAS_PENDING_CONN | WRC_RETRY_MSG | WRC_SCM_IN_PROG);
  chan->wrc_msg_sz = 0;
}

void cancel_pending_writes(struct wrtcchan *chan) {
  struct epoll_event ev;
  int err;

  chan->wrc_flags &= ~(WRC_HAS_OUTGOING | WRC_RETRY_MSG | WRC_ERROR_ON_RETRY);
  chan->wrc_msg_sz = 0;
  chan->wrc_retries_left = 0;
  chan->wrc_retry_rsp = 0;

  ev.events = DFL_EPOLL_EVENTS;
  ev.data.ptr = (void *) chan;

  if ( chan->wrc_flags & (WRC_WAIT_FOR_SCTP_OUT | WRC_HAS_PENDING_CONN) )
    ev.events &= ~EPOLLIN;

  err = epoll_ctl(g_epollfd, EPOLL_CTL_MOD, chan->wrc_sk, &ev);
  if ( err == -1 ) {
    perror("cancel_pending_writes: epoll_ctl");
  }
}

void chan_sctp_sndrcvinfo(struct wrtcchan *chan, struct sctp_sndrcvinfo *si) {
  memset(si, 0, sizeof(*si));
  si->sinfo_stream = WEBRTC_SERVER_SID(chan->wrc_chan_id);
  si->sinfo_flags = 0;
  si->sinfo_ppid = htonl(WEBRTC_BINARY_PPID);
  si->sinfo_context = chan->wrc_chan_id;
  si->sinfo_assoc_id = g_webrtc_assoc;
}

int chan_supports_sk_type(struct wrtcchan *chan, int sk_type) {
  switch ( chan->wrc_ctype ) {
  case DATA_CHANNEL_RELIABLE: return 1;
  case DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED:
  case DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED:
  case DATA_CHANNEL_RELIABLE_UNORDERED:
    return sk_type == SOCK_DGRAM;
  case DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT:
  case DATA_CHANNEL_PARTIAL_RELIABLE_TIMED:
    return sk_type == SOCK_SEQPACKET || sk_type == SOCK_DGRAM;
  default: return 0;
  }
}

const char *chan_status_str(uint8_t s) {
  switch (s) {
  case WEBRTC_STS_INVALID:   return "WEBRTC_STS_INVALID";
  case WEBRTC_STS_VALID:     return "WEBRTC_STS_VALID";
  case WEBRTC_STS_OPEN:      return "WEBRTC_STS_OPEN";
  case WEBRTC_STS_CONNECTED: return "WEBRTC_STS_CONNECTED";
  default: return "Unknown";
  }
}

const char *sk_family_str(int family) {
  switch (family) {
  case AF_INET:  return "AF_INET";
  case AF_INET6: return "AF_INET6";
  case AF_UNIX:  return "AF_UNIX";
  default:       return "Unknown";
  }
}

const char *sk_type_str(int family) {
  switch (family) {
  case SOCK_STREAM:    return "SOCK_STREAM";
  case SOCK_DGRAM:     return "SOCK_DGRAM";
  case SOCK_SEQPACKET: return "SOCK_SEQPACKET";
  default:             return "Unknown";
  }
}

const char *wrtc_ctype_str(uint8_t ctype) {
  switch (ctype) {
  case DATA_CHANNEL_RELIABLE: return "DATA_CHANNEL_RELIABLE";
  case DATA_CHANNEL_RELIABLE_UNORDERED: return "DATA_CHANNEL_RELIABLE_UNORDERED";
  case DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT: return "DATA_CHANNEL_RELIABLE_REXMIT";
  case DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED: return "DATA_CHANNEL_RELIABLE_REXMIT_UNORDERED";
  case DATA_CHANNEL_PARTIAL_RELIABLE_TIMED: return "DATA_CHANNEL_PARTIAL_RELIABLE_TIMED";
  case DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED: return "DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED";
  default: return "Unknown";
  }
}

static inline void dbg_chan(struct wrtcchan *chan) {
#if WEBRTC_PROXY_DEBUG
  fprintf(stderr, "WebRTC channel %d\n", chan->wrc_chan_id);
  fprintf(stderr, "  Status: %s\n", chan_status_str(chan->wrc_sts));
  fprintf(stderr, "    Type: %s\n", wrtc_ctype_str(chan->wrc_ctype));
  fprintf(stderr, "    Prio: %u\n", chan->wrc_prio);
  fprintf(stderr, "     Rel: %u\n", chan->wrc_rel);
  fprintf(stderr, "   Label: %.*s\n", WEBRTC_NAME_MAX, chan->wrc_label);
  fprintf(stderr, "   Proto: %.*s\n", WEBRTC_NAME_MAX, chan->wrc_proto);
  fprintf(stderr, "  Family: %s(%d)\n", sk_family_str(chan->wrc_family), chan->wrc_family);
  fprintf(stderr, "    Type: %s(%d)\n", sk_type_str(chan->wrc_type), chan->wrc_type);
  fprintf(stderr, "  Socket: %d\n", chan->wrc_sk);
#endif
}

static inline void dbg_assoc_change(struct sctp_assoc_change *sac, int sz) {
  //  int ft_cnt = sz - sizeof(*sac), i;
#if WEBRTC_PROXY_DEBUG
  fprintf(stderr, "SCTP Association change:\n");
  fprintf(stderr, "  - Num outbound: %d\n", sac->sac_outbound_streams);
  fprintf(stderr, "  -  Num inbound: %d\n", sac->sac_inbound_streams);
  fprintf(stderr, "  -     Assoc ID: %d\n", sac->sac_assoc_id);
  fprintf(stderr, "  -     Supports: ");
#endif
//  for ( i = 0; i < ft_cnt; ++i )
//    switch ( fts[i] ) {
//    case SCTP_PR_SUPPORTED:
//      fprintf(stderr, "Partial reliability; ");
//      break;
//    case SCTP_ASSOC_SUPPORTS_AUTH:
//      fprintf(stderr, "Auth; ");
//      break;
//    case SCTP_ASSOC_SUPPORTS_ASCONF:
//      fprintf(stderr, "ASCONF; ");
//      break;
//    case SCTP_ASSOC_SUPPORTS_MULTIBUF:
//      fprintf(stderr, "Multibuf; ");
//      break;
//    case  SCTP_ASSOC_SUPPORTS_RE_CONFIG:
//      fprintf(stderr, "Reconfig; ");
//      break;
//    default: break;
//    }
  fprintf(stderr, "\n");
}

void set_sk_nonblocking(int sk) {
  int flags = fcntl(sk, F_GETFL);
  if ( flags == -1 ) {
    perror("fcntl F_GETFL");
    return;
  }

  flags = fcntl(sk, F_SETFL, flags | O_NONBLOCK);
  if ( flags == -1 ) {
    perror("fcntl F_SETFL | O_NONBLOCK");
    return;
  }
}

// EPOLL thread
int stkdmsg_has_enough(struct stkdmsg *msg, int sz) {
  if ( sz < 4 ) return 0;

  if ( STKD_IS_RSP(msg) && STKD_IS_ERROR(msg) )
    return sz >= STKD_ERROR_MSG_SZ;

  switch ( STKD_REQ(msg) ) {
  case STKD_OPEN_APP_REQUEST:
    if ( STKD_IS_RSP(msg) ) {
      return sz >= STKD_OPENED_APP_RSP_SZ;
    }
  default:
    return 1;
  }
}

int stkcmsg_has_enough(struct stkcmsg *msg, int sz) {
  if ( sz < 1 ) return 0;

  switch ( STK_CMSG_REQ(msg) ) {
  case SCM_REQ_OPEN_APP:
    if ( STK_CMSG_IS_RSP(msg) )
      return sz <= SCM_OPENED_APP_RSP_SZ;
    else {
      uint32_t appnmlen = ntohl(msg->data.scm_open_app_request.scm_app_len);

      if ( sz < SCM_OPEN_APP_REQ_SZ_MIN ) return 0;

      return sz >= (SCM_OPEN_APP_REQ_SZ_MIN + appnmlen);
    }
  case SCM_REQ_CONNECT:
    if ( STK_CMSG_IS_RSP(msg) )
      return sz >= SCM_CONNECT_RSP_SZ;
    else
      return sz >= SCM_CONNECT_REQ_SZ;
  case SCM_REQ_DATA:
    if ( STK_CMSG_IS_RSP(msg) )
      return 0; // No response for DATA messages
    else return sz >= SCM_DATA_REQ_SZ;
  default:
    return sz >= sizeof(*msg);
  }
}

int receive_ctl_rsp(int srv, struct wrtcchan *chan) {
#if WEBRTC_PROXY_DEBUG
  char addr_buf[INET6_ADDRSTRLEN]; // For forwards compatibility
#endif
  int err, rsp_sz;
  struct sctp_sndrcvinfo sri;

  struct stkdmsg *msg = (struct stkdmsg *) chan->wrc_proxy_buf;
  struct stkcmsg rsp;

  chan_sctp_sndrcvinfo(chan, &sri);

  if ( chan->wrc_proxy_buf_sz == 0 ) {
    err = recv(chan->wrc_sk, chan->wrc_proxy_buf + chan->wrc_proxy_buf_sz,
               PROXY_BUF_SIZE - chan->wrc_proxy_buf_sz, MSG_DONTWAIT);
    if ( err < 0 ) {
      perror("receive_ctl_rsp: recv");
      return -1;
    }

    if ( err == 0 ) return 0;
  } else
    err = chan->wrc_proxy_buf_sz; // Data already read, but we could not send a response

  if ( stkdmsg_has_enough(msg, err) ) {
    if ( STKD_IS_RSP(msg) ) {
      switch ( STKD_REQ(msg) ) {
      case STKD_OPEN_APP_REQUEST:
        if ( STKD_IS_ERROR(msg) ) {
          log_printf("Got open app error %d for channel %d\n",
                     ntohl(msg->sm_data.sm_error), chan->wrc_chan_id);
          rsp.scm_type = SCM_ERROR | SCM_RESPONSE | SCM_REQ_OPEN_APP;
          rsp.data.scm_error = msg->sm_data.sm_error;
          rsp_sz = SCM_ERROR_RSP_SZ;
        } else {
          log_printf("Got open app response in family %s: %s\n",
                     sk_family_str(ntohl(msg->sm_data.sm_opened_app.sm_family)),
                     inet_ntop(ntohl(msg->sm_data.sm_opened_app.sm_family),
                               &msg->sm_data.sm_opened_app.sm_addr,
                               addr_buf, sizeof(addr_buf)));

          rsp.scm_type = SCM_RESPONSE | SCM_REQ_OPEN_APP;
          rsp_sz = SCM_OPENED_APP_RSP_SZ;
          err = get_address_descriptor(msg->sm_data.sm_opened_app.sm_addr);
          if ( err < 0 ) {
            rsp.scm_type |= SCM_ERROR;
            rsp.data.scm_error = htonl(STKD_ERROR_NO_SPACE);
            rsp_sz = SCM_ERROR_RSP_SZ;
          } else {
            rsp.data.scm_opened_app = htonl(err);
          }
        }

        // Because the message was responded to, we can clear out
        // any pending writes
        //
        // Note, that the epoll event loop may still wake up for
        // this, but it will notice that nothing is present in the
        // output buffer and it will wait.
        cancel_pending_writes(chan);
//        memcpy(chan->wrc_proxy_buf, &rsp, rsp_sz);
//        chan->wrc_proxy_buf_sz = rsp_sz;
        break;

      default:
        log_printf("Unknown storkd request type: %d\n", STKD_REQ(msg));
        return -1;
      }
    } else {
      log_printf("Got request from storkd: %08x (TODO)\n", ntohl(msg->sm_flags));
      return 0;
    }
  } else {
    log_printf("Not enough data in storkd response\n");
    return -1;
  }


  if ( chan->wrc_flags & WRC_SCM_IN_PROG ) {
    err = sctp_send(srv, (void *) &rsp, rsp_sz, &sri, 0);
    if ( err < 0 ) {
      if ( errno == EAGAIN || errno == EWOULDBLOCK )
        return rsp_sz;
      else {
        perror("proxy_data(cmsg): sctp_send");
        return -1;
        // TODO close the channel or something
      }
    } else if ( err == 0 )
      return rsp_sz;
  }

  chan->wrc_proxy_buf_sz = 0;
  chan->wrc_flags &= ~WRC_SCM_IN_PROG;

  return 0;
}

int proxy_stream_socket(int srv, struct wrtcchan *chan, int *events) {
  int bytes_read, bytes_written, buffer_available;

  buffer_available = PROXY_BUF_SIZE - chan->wrc_proxy_buf_sz;
  log_printf("proxy_data stream %d\n", buffer_available);
  assert(buffer_available >= 0);

  bytes_read = recv(chan->wrc_sk, chan->wrc_proxy_buf + chan->wrc_proxy_buf_sz,
                    buffer_available, MSG_DONTWAIT);
  if ( bytes_read < 0 ) {
    if ( errno != EAGAIN && errno != EWOULDBLOCK ) {
      perror("proxy_stream_socket: recv");
      return -1;
    }
  } else if ( bytes_read == 0 ) {
    log_printf("Did not read anything\n");
    if ( chan->wrc_flags & WRC_READ_CLOSED ) {
      if ( !chan_has_more_proxying(chan) ) {
        mark_channel_closed(chan);
        *events = 0;
        return 0;
      }
    }
  } else {
    chan->wrc_proxy_buf_sz += bytes_read;
    log_printf("Received %d bytes. Buffer is now %d\n", bytes_read, chan->wrc_proxy_buf_sz);
  }

  if ( chan->wrc_proxy_buf_sz > 0 ) {
    struct sctp_sndrcvinfo sri;
    chan_sctp_sndrcvinfo(chan, &sri);

    bytes_written = sctp_send(srv, (void *)chan->wrc_proxy_buf, chan->wrc_proxy_buf_sz, &sri, MSG_DONTWAIT);
    if ( bytes_written < 0 ) {
      if ( errno == EAGAIN || errno == EWOULDBLOCK ) {
	log_printf("Writing this packet would block, so we're requesting time\n");
        chan->wrc_flags |= WRC_HAS_OUTGOING;
        assert(chan->wrc_proxy_buf_sz >= 0);
        return chan->wrc_proxy_buf_sz;
      } else {
        perror("proxy_stream_socket: sctp_send");
        return -1;
      }
    } else if ( bytes_written < chan->wrc_proxy_buf_sz ) {
      log_printf("Only able to write %d of %d bytes. Waiting\n", bytes_written, chan->wrc_proxy_buf_sz);
      chan->wrc_flags |= WRC_HAS_OUTGOING;
      chan->wrc_proxy_buf_sz -= bytes_written;
      memmove(chan->wrc_proxy_buf, chan->wrc_proxy_buf + bytes_written, chan->wrc_proxy_buf_sz - bytes_written);
      return chan->wrc_proxy_buf_sz;
    } else {
      chan->wrc_proxy_buf_sz = 0;
      chan->wrc_flags &= ~WRC_HAS_OUTGOING;
      return 0;
    }
  } else {
    fprintf(stderr, "Nothing in buffer\n");
    return 0;
  }
}

// proxy_buf is of size PROXY_BUF_SIZE
int proxy_data(int srv, struct wrtcchan *chan, int *events) {
  if ( chan->wrc_flags & WRC_CONTROL ) {
    return receive_ctl_rsp(srv, chan);
  } else {
    switch ( chan->wrc_type ) {
    case SOCK_DGRAM:
      fprintf(stderr, "proxy_data: TODO dgram\n");
      return -1; //return proxy_dgram_socket(srv, chan);

    case SOCK_STREAM:
      return proxy_stream_socket(srv, chan, events);

    default:
      fprintf(stderr, "Can't proxy data on unknown connection type %d\n", chan->wrc_type);
      mark_channel_closed(chan);
      return -1;
    }
  }
}

int send_connection_opens_rsp(int srv, struct wrtcchan *chan) {
  struct stkcmsg rsp;
  struct sctp_sndrcvinfo sri;
  int err;

  rsp.scm_type = SCM_RESPONSE | SCM_REQ_CONNECT;

  chan_sctp_sndrcvinfo(chan, &sri);

  err = sctp_send(srv, (void *)&rsp, SCM_CONNECT_RSP_SZ, &sri, MSG_DONTWAIT);
  if ( err < 0 ) {
    if ( errno == EAGAIN || errno == EWOULDBLOCK ) {
      return SCM_CONNECT_RSP_SZ;
    } else {
      perror("send_connection_opens_rsp: sctp_send");
      // TODO close the channel?
      return -1;
    }
  } else
    return 0;
}

void flush_chan(int srv, struct wrtcchan *chan, int *new_events, int *needs_write_space) {
  int err, old_sk;

  if ( chan->wrc_flags & WRC_HAS_PENDING_CONN ) {
    struct wrcpendingconn *pconn = (struct wrcpendingconn *) chan->wrc_buffer;

    log_printf("Reattempting connection on channel %d\n", chan->wrc_chan_id);
    assert(chan->wrc_msg_sz == sizeof(struct wrcpendingconn));

    err = mk_socket(chan->wrc_type);
    if ( err < 0 ) {
      mark_channel_closed(chan);
      *new_events = 0;
      return;
    }

    disarm_channel(chan);

    old_sk = chan->wrc_sk;
    chan->wrc_sk = err;
    close(old_sk);

    arm_channel(chan);

    err = connect_socket(chan, &pconn->wpc_sin);
    if ( err < 0 ) {
      int scm_error = errno;
      perror("connect_socket");

      scm_error = translate_stk_connection_error(scm_error);

      rsp_cmsg_error(srv, chan, SCM_REQ_CONNECT, scm_error);
      chan->wrc_flags &= ~(WRC_RETRY_MSG | WRC_HAS_PENDING_CONN);

      // TODO mark channel closed
      mark_channel_closed(chan);
      *new_events = 0;
    } else if ( err == 0 ) {
      log_printf("Successfully opened channel %d\n", chan->wrc_chan_id);
      mark_channel_connected(chan);
      err = send_connection_opens_rsp(srv, chan);
      if ( err < 0 ) {
        fprintf(stderr, "flush_chan: could not send connection opens response\n");
      } else if ( err > 0 ) {
        fprintf(stderr, "flush_chan: Going to delay connection opens response\n");

        // Needs availability on SCTP channel
        if ( err > *needs_write_space )
          *needs_write_space = err;

        chan->wrc_flags |= WRC_NEEDS_CONN_OPENS_RSP;
      }
    } else
      wait_for_write_on_chan(chan);

    // Connection is in progress now; wait and return
  } else if ( chan->wrc_flags & WRC_HAS_OUTGOING ) {
    log_printf("Flushing channel %d of type %s\n", chan->wrc_chan_id, sk_type_str(chan->wrc_type));

    if ( chan->wrc_flags & WRC_NEEDS_CONN_OPENS_RSP ) {
      err = send_connection_opens_rsp(srv, chan);
      if ( err < 0 ) {
        fprintf(stderr, "flush_chan: could not send connection opens response\n");
        return;
      } else if ( err > 0 ) {
        if ( err > *needs_write_space )
          *needs_write_space = err;

        return;
      }

      chan->wrc_flags &= ~WRC_NEEDS_CONN_OPENS_RSP;
    }

    if ( chan->wrc_msg_sz == 0 ) {
      // If there is no message, we are only doing this for the state
      // transitions. Return immmediately
      //
      // TODO do we need empty data grams??

      chan->wrc_flags &= ~WRC_HAS_OUTGOING;

      return;
    }

    switch ( chan->wrc_type ) {
    case SOCK_DGRAM:
      // Send the datagram
      err = send(chan->wrc_sk, chan->wrc_buffer, chan->wrc_msg_sz, 0);
      if ( err < 0 ) {
        perror("send SOCK_DGRAM");
      }

      chan->wrc_flags &= ~WRC_HAS_OUTGOING;
      if ( chan->wrc_flags & WRC_RETRY_MSG ) {
        if ( clock_gettime(CLOCK_REALTIME, &chan->wrc_last_msg_sent) < 0 ) {
          perror("flush_chan: clock_gettime");
        }

        if ( chan->wrc_retries_left == 0 ) {
          chan->wrc_msg_sz = 0;
          log_printf("No more retries left for datagram\n");
          if ( chan->wrc_flags & WRC_ERROR_ON_RETRY ) {
            log_printf("An error was requested to be delivered on retry failure\n");
            rsp_cmsg_error(srv, chan, chan->wrc_retry_rsp, STKD_ERROR_TEMP_UNAVAILABLE);
          }
          chan->wrc_flags &= ~(WRC_RETRY_MSG | WRC_ERROR_ON_RETRY);
        } else {
          chan->wrc_retries_left--;
          chan->wrc_retry_interval_millis *= 2;
        }
      } else
        chan->wrc_msg_sz = 0;
      break;
    case SOCK_STREAM:
      // Retries are ignored on SOCK_STREAM
      chan->wrc_retries_left = 0;
      chan->wrc_flags &= ~(WRC_RETRY_MSG | WRC_ERROR_ON_RETRY);

      log_printf("Sent buffer of size %ld\n%.*s", chan->wrc_msg_sz, (int)chan->wrc_msg_sz, chan->wrc_buffer);

      err = send(chan->wrc_sk, chan->wrc_buffer, chan->wrc_msg_sz, 0);
      if ( err < 0 ) {
        if ( errno == EAGAIN || errno == EWOULDBLOCK ) {
          // These indicate that the socket was not truly read
          *new_events |= EPOLLOUT;
        } else {
          perror("send SOCK_STREAM");
        }
      } else {
        chan->wrc_msg_sz -= err;
        if ( chan->wrc_msg_sz == 0 ) {
          // All bytes were written
          chan->wrc_flags &= ~WRC_HAS_OUTGOING;
        } else {
          // Not all bytes were written
          log_printf("Only %d bytes were sent\n", err);
          memcpy(chan->wrc_buffer, chan->wrc_buffer + err, chan->wrc_msg_sz);
          *new_events |= EPOLLOUT;
        }
      }
      break;
    default:
      fprintf(stderr, "flush_chan: invalid socket type %d\n", chan->wrc_type);
      chan->wrc_flags &= ~(WRC_HAS_OUTGOING | WRC_RETRY_MSG);
      chan->wrc_retries_left = 0;
      return;
    }

  }
}

void state_transition(int srv, struct wrtcchan *chan, int epev) {
  // Perform necessary transitions
  if ( chan->wrc_sts == WEBRTC_STS_OPEN && (epev & EPOLLOUT) &&
       !(epev & EPOLLRDHUP) && !(epev & EPOLLHUP)) {
    log_printf("Marking channel %d as connected\n", chan->wrc_chan_id);

    mark_channel_connected(chan);
    // Typically, we want to send some kind of success msg here as well
    send_connection_opens_rsp(srv, chan);
  }
}

// Run when we get a EPOLLRDHUP or EPOLLHUP on the socket
int chan_disconnects(int srv, struct wrtcchan *chan, int triggers, int *evts) {
  int sockerr, cerr, err;
  socklen_t sockerrlen = sizeof(sockerr);

  if ( chan->wrc_sts == WEBRTC_STS_OPEN && chan->wrc_flags & WRC_HAS_PENDING_CONN ) {
    // Get socket error. Retry if the error is temporary and we have retries left
    err = getsockopt(chan->wrc_sk, SOL_SOCKET, SO_ERROR, &sockerr, &sockerrlen);
    if ( err < 0 ) {
      perror("getsockopt SO_ERROR");
      sockerr = errno;
    }

    if ( sockerr == 0 ) {
      // log_printf("Got HUP or RDHUP but there was no socket error %d %d\n",
      //            triggers & EPOLLHUP, triggers & EPOLLRDHUP);
      // *evts &= ~(EPOLLHUP | EPOLLRDHUP);
      sched_yield();
      return 0;
    } else {
      log_printf("Closing socket due to error: %s (%d retries_left)\n", strerror(sockerr), chan->wrc_retries_left);

      cerr = translate_stk_connection_error(sockerr);

      if ( chan->wrc_retries_left > 0 && STKD_ERR_IS_TEMPORARY(cerr) ) {
        // set the channel with WRC_HAS_OUTGOING, which causes a new
        // connect to be issued
        chan->wrc_retries_left--;
        chan->wrc_retry_interval_millis *= 2;
        chan->wrc_flags |= WRC_RETRY_MSG;
        log_printf("Marked channel %d for connection retry\n", chan->wrc_chan_id);
        *evts = 0; // This prevents a tight loop
        return 0;
      } else {
        chan->wrc_sts = WEBRTC_STS_VALID;
        chan->wrc_flags &= ~(WRC_RETRY_MSG | WRC_HAS_PENDING_CONN);
        rsp_cmsg_error(srv, chan, SCM_REQ_CONNECT, cerr);
        return -1;
      }
    }
  } else if ( chan->wrc_sts == WEBRTC_STS_CONNECTED ) {
    log_printf("Got HUP while channel is connected\n");

    // Mark the channel as read_closed
    if ( chan_has_more_proxying(chan) ) {
      log_printf( "Just marking closed\n");
      chan->wrc_flags |= WRC_READ_CLOSED;
      return 0;
    } else {
      mark_channel_closed(chan);
      return -1;
    }
  } else abort();
}

#define UPDATE_TIMEOUT(timeout, millis)     \
  (timeout) = ((timeout) == -1 ? (millis) : ((timeout) > (millis) ? (millis) : (timeout)))

int chan_needs_retry(struct wrtcchan *chan, struct timespec *now,
                      int *timeout) {
  if ( chan->wrc_flags & WRC_RETRY_MSG ) {
    if ( chan->wrc_retries_left == 0 ) {
      chan->wrc_flags &= ~WRC_RETRY_MSG;
      return 0;
    } else {
      struct timespec when, ri;

      millis_to_timespec(&ri, chan->wrc_retry_interval_millis);
      //      log_printf("channel retry interval is %d\n", chan->wrc_retry_interval_millis);
      timespec_add(&when, &chan->wrc_last_msg_sent, &ri);

      //      log_printf("comparing times (%lu,%lu) < (%lu, %lu)\n", now->tv_sec, now->tv_nsec, when.tv_sec, when.tv_nsec);

      if ( timespec_lt(&when, now) ) {
        // If the time to retry is less than now, we need to retry
        chan->wrc_flags |= WRC_HAS_OUTGOING;
        return 1;
      } else {
        // Approximate how much time we need to wait until this needs a retry
        int timeout_millis;
        timeout_millis = (when.tv_sec * 1000 + (when.tv_nsec / 1000000));
        timeout_millis -= (now->tv_sec * 1000 + (now->tv_nsec / 1000000));

        //log_printf("We have %d milliseconds until we need to wake up\n", timeout_millis);

        UPDATE_TIMEOUT(*timeout, timeout_millis);

        return 0;
      }
    }
  } else
    return 0;
}

int do_pending_proxies(int srv) {
  struct wrtcchan *cur;
  int err, ret = -1;

  //fprintf(stderr, "do pending proxies\n");

  CONSUME_STACK(&g_pending_reads, cur, struct wrtcchan, wrc_pending_reads) {
    int new_events = DFL_EPOLL_EVENTS;

    err = proxy_data(srv, cur, &new_events);
    if ( err < 0 ) {
      fprintf(stderr, "do_pending_reads: error while proxying data\n");
    } else if ( err > 0 ) {
      fprintf(stderr, "do_pending_reads: could not complete proxy for %d\n", cur->wrc_chan_id);
      return err;
    } else {
      if ( new_events ) {
        struct epoll_event ev;
        ev.events = new_events;
        ev.data.ptr = cur;

        if ( cur->wrc_flags & WRC_HAS_OUTGOING )
          ev.events |= EPOLLOUT;

        err = epoll_ctl(g_epollfd, EPOLL_CTL_MOD, cur->wrc_sk, &ev);
        if ( err < 0 ) {
          perror("do_pending_proxies: epoll_ctl");
        } else {
          ret = 0;
        }

        cur->wrc_flags &= ~WRC_WAIT_FOR_SCTP_OUT;
      } else
        ret = 0;
    }
  }

  return ret;
}

int main_loop(int srv) {
  struct epoll_event evs[MAX_EPOLL_EVENTS];
  int i, ev_cnt = 0, timeout = -1, err;
  struct timespec now;
  sigset_t block, old;

  fprintf(stderr, "WebRTC epoll thread starts on port %d\n", g_dbg_port);

  sigfillset(&block);
  err = sigprocmask(SIG_SETMASK, &block, &old);
  if ( err != 0 ) {
    errno = err;
    perror("sigmask SIG_SETMASK");
    return 20;
  }

  sigdelset(&old, SIGTERM);
  sigdelset(&old, SIGINT);
  sigdelset(&old, SIGQUIT);
  sigdelset(&old, SIGHUP);

  g_epollfd = epoll_create1(EPOLL_CLOEXEC);
  if ( g_epollfd < 0 ) {
    perror("epoll_create1");
    return 4;
  }

  // We'll want subscriptions on the main SCTP socket
  arm_sctp(srv);

  while (1) {
    int ofs, needs_write_space = 0;

    log_printf("Epoll with timeout: %d\n", timeout);
    ev_cnt = epoll_pwait(g_epollfd, evs, MAX_EPOLL_EVENTS, timeout, &old);
    if ( ev_cnt == -1 ) {
      if ( errno == EINTR ) {
        log_printf("Received EPOLL interrupt\n");
        continue;
      } else {
        perror("epoll_wait");
        return 6;
      }
    }
    log_printf("Finished epoll wait: %d\n", ev_cnt);

    timeout = -1;

    ofs = rand();

    // Go over each event in the epoll and continue
    for ( i = 0; i < ev_cnt; ++i ) {
      struct epoll_event *ev = evs + ((i + ofs) % ev_cnt) ;
      struct wrtcchan *chan = (struct wrtcchan *) ev->data.ptr;
      int new_events = DFL_EPOLL_EVENTS;

      if ( !chan ) {
        log_printf("Got epoll for sctp: %08x %d %d %d\n",
                   ev->events,
                   ev->events & EPOLLIN,
                   ev->events & EPOLLOUT,
                   ev->events & EPOLLHUP);

        if ( ev->events & EPOLLIN ) {
          err = receive_sctp(srv);
          if ( err < 0 ) {
            fprintf(stderr, "Could not receive SCTP message\n");
            return -1;
          }
        }

        if ( ev->events & EPOLLOUT ) {
          perform_delayed_closes(srv);

          err = do_pending_proxies(srv);
          if ( err > needs_write_space )
            needs_write_space = err;
        }

        ev->events = DFL_EPOLL_EVENTS;
        //fprintf(stderr, "Set SCTP trigger %d %d %d\n", !!needs_write_space,
        //        !!g_pending_reads.next, !!g_pending_free_channels.next);
        if ( needs_write_space ||
             g_pending_reads.next ||
             g_pending_free_channels.next )
          ev->events |= EPOLLOUT;
        err = epoll_ctl(g_epollfd, EPOLL_CTL_MOD, srv, ev);
        if ( err < 0 ) {
          perror("epoll_ctl EPOLL_CTL_MOD srv");
        }
      } else {
        log_printf("Got epoll for %d %d\n", chan->wrc_chan_id, ev->events);

        state_transition(srv, chan, ev->events);

        if ( chan->wrc_flags & (WRC_WAIT_FOR_SCTP_OUT | WRC_HAS_PENDING_CONN) )
          new_events &= ~EPOLLIN;

        if ( ev->events & EPOLLIN ) {
          log_printf("proxy_data %d\n", chan->wrc_chan_id);
          // We have data ready for reading. Read the data and send it
          // out on the channel.
          err = proxy_data(srv, chan, &new_events);
          if ( err < 0 ) {
            fprintf(stderr, "proxy_data: failed on channel %d\n", chan->wrc_chan_id);
          } else if ( err ) {
            if ( err > needs_write_space )
              needs_write_space = err;

            new_events &= ~EPOLLIN;
            chan->wrc_flags |= WRC_WAIT_FOR_SCTP_OUT;

            PUSH_STACK(&g_pending_reads, chan, wrc_pending_reads);
          }
        }

        if ( ev->events & (EPOLLHUP | EPOLLRDHUP) ) {
          if ( !((ev->events & EPOLLRDHUP) &&
                 (chan->wrc_flags & WRC_READ_CLOSED )) ) {
            err = chan_disconnects(srv, chan, ev->events, &new_events);
            if ( err != 0 ) {
              continue;
            }
          }

          if ( chan->wrc_flags & WRC_WRITE_CLOSED )
            continue;
        }

        if ( (ev->events & EPOLLOUT) ||
             (chan->wrc_flags & WRC_NEEDS_CONNECT) ) {
          // The socket can be written to. Flush any pending messages
          flush_chan(srv, chan, &new_events, &needs_write_space);

          if ( (chan->wrc_flags & WRC_READ_CLOSED) &&
               !chan_has_more_proxying(chan) ) {
            mark_channel_closed(chan);
            new_events = 0;
          }

          chan->wrc_flags &= ~WRC_NEEDS_CONNECT;
        }

        // Rearm the channel

        if ( new_events != 0 ) {
          int orig_ev = ev->events;
          ev->events = new_events;
          err = epoll_ctl(g_epollfd, EPOLL_CTL_MOD, chan->wrc_sk, ev);
          if ( err < 0 ) {
            perror("epoll_ctl EPOLL_CTL_MOD");
            fprintf(stderr, "While registering %x for %d (id %d)\n", new_events, chan->wrc_sk, chan->wrc_chan_id);
            fprintf(stderr, "we were originally responding to %x (%x, %x, %x)\n", orig_ev, EPOLLIN, EPOLLOUT, EPOLLHUP);
          }
        }
      }
    }

    // If we need more space in the write buffer or we have a reset to
    // send, wait for the ability to write
    if ( needs_write_space ||
         g_pending_free_channels.next ) {
      struct epoll_event srv_ev;
      srv_ev.events = DFL_EPOLL_EVENTS | EPOLLOUT;
      srv_ev.data.ptr = NULL;

      //fprintf(stderr, "Needs write space in SCTP socket\n");

      err = epoll_ctl(g_epollfd, EPOLL_CTL_MOD, srv, &srv_ev);
      if ( err < 0 ) {
        perror("epoll_ctl EPOLL_CTL_MOD srv");
      }
    }

    // Now, go over all open channels and if a timeout has expired,
    // mark the socket as waiting for output as well
    if ( clock_gettime(CLOCK_REALTIME, &now) < 0 ) {
      perror("clock_gettime now");
      return 10;
    }

    for ( i = 0, timeout = -1; i < g_num_strms; ++i )
      if ( g_channel_htbl[i] ) {
        if ( chan_needs_retry(g_channel_htbl[i], &now, &timeout) ) {
          log_printf("WebRTC channel is requesting retry %d %d\n",
                     g_channel_htbl[i]->wrc_chan_id, timeout);
          if ( g_channel_htbl[i]->wrc_flags & WRC_HAS_PENDING_CONN )
            g_channel_htbl[i]->wrc_flags |= WRC_NEEDS_CONNECT;
          wait_for_write_on_chan(g_channel_htbl[i]);
        }
      }
  }
}

// SCTP Server

void warn_if_ext_not_supported(int srv, const char *nm, int opt) {
  struct sctp_assoc_value val;
  socklen_t val_sz = sizeof(val);

  val.assoc_id = g_webrtc_assoc;
  val.assoc_value = 0;

  if ( getsockopt(srv, IPPROTO_SCTP, opt,
                  &val, &val_sz) < 0 ) {
    perror("warn_if_ext_not_supported: getsockopt");
  }

  if ( !val.assoc_value )
    fprintf(stderr, "Association does not support %s\n", nm);
  else
    fprintf(stderr, "Association supports %s\n", nm);
}

void handle_assoc_change(int srv, struct sctp_assoc_change *sac, int sz) {
  if ( sz < sizeof(*sac) ) return;

  switch ( sac->sac_state ) {
  case SCTP_COMM_UP:
    dbg_assoc_change(sac, sz);
    if ( g_webrtc_assoc != SCTP_FUTURE_ASSOC ) {
      int assoc;
      // Close this association
      fprintf(stderr, "Received another association: %d\n", sac->sac_assoc_id);
      assoc = sctp_peeloff(srv, sac->sac_assoc_id);
      if ( assoc < 0 ) {
        perror("sctp_peeloff");
        return;
      }

      if ( shutdown(assoc, SHUT_RDWR) < 0 ) {
        perror("shutdown");
        return;
      }
    } else {
      struct sctp_assoc_value sched;
      struct sctp_paddrparams spp;
      struct sockaddr_in any_ip;
      socklen_t optlen;

      g_webrtc_assoc = sac->sac_assoc_id;
      warn_if_ext_not_supported(srv, "SCTP reconfig", SCTP_RECONFIG_SUPPORTED);
      warn_if_ext_not_supported(srv, "SCTP partial reliability", SCTP_PR_SUPPORTED);

      sched.assoc_id = g_webrtc_assoc;
      sched.assoc_value = SCTP_SS_PRIO;
      if ( setsockopt(srv, IPPROTO_SCTP, SCTP_STREAM_SCHEDULER, &sched, sizeof(sched)) < 0 ) {
        perror("setsockopt SCTP_PLUGGABLE_SS");
      }

      sched.assoc_id = g_webrtc_assoc;
      sched.assoc_value = SCTP_ENABLE_RESET_STREAM_REQ | SCTP_ENABLE_RESET_ASSOC_REQ |
        SCTP_ENABLE_CHANGE_ASSOC_REQ;
      if ( setsockopt(srv, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &sched, sizeof(sched)) < 0) {
        perror("setsockopt SCTP_ENABLE_STREAM_RESET");
      }

      sched.assoc_id = g_webrtc_assoc;
      sched.assoc_value = 0;
      optlen = sizeof(sched);
      if ( getsockopt(srv, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &sched, &optlen) < 0 ) {
        perror("getsockopt SCTP_ENABLE_STREAM_RESET");
      } else
        fprintf(stderr, "SCTP_ENABLE_STREAM_RESET value: %x\n", sched.assoc_value);

      any_ip.sin_family = AF_INET;
      any_ip.sin_port = 0;
      any_ip.sin_addr.s_addr = INADDR_ANY;

      memset(&spp, 0, sizeof(spp));
      spp.spp_assoc_id = g_webrtc_assoc;
      memcpy(&spp.spp_address, &any_ip, sizeof(any_ip));
      spp.spp_hbinterval = 30000; // Send a heartbeat every ten seconds
      spp.spp_pathmaxrxt = 5;
      if ( setsockopt(srv, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &spp, sizeof(spp)) < 0 ) {
        perror("setsockopt SCTP_PEER_ADDR_PARAMS");
      }


      g_num_strms = (sac->sac_outbound_streams < sac->sac_inbound_streams ?
                     sac->sac_inbound_streams : sac->sac_outbound_streams);
      g_channels = calloc(sizeof(*g_channels), g_num_strms);
      if ( !g_channels ) {
        perror("calloc g_channels");
        exit(200);
      }

      g_channel_htbl = calloc(sizeof(*g_channel_htbl), g_num_strms);
      if ( !g_channel_htbl ) {
        perror("calloc g_channel_htbl");
        exit(201);
      }

      g_closing_chans = calloc(sizeof(*g_closing_chans), g_num_strms);
      if ( !g_closing_chans ) {
        perror("calloc g_closing_chans");
        exit(202);
      }
      memset(g_closing_chans, 0xFF, sizeof(*g_closing_chans) * g_num_strms);
    }
    break;
  case SCTP_COMM_LOST:
    fprintf(stderr, "SCTP comm lost: error %d\n", sac->sac_error);
    exit(20);
    break;
  case SCTP_RESTART:
    fprintf(stderr, "WARNING: SCTP restart detected (TODO)\n");
    break;
  case SCTP_SHUTDOWN_COMP:
    fprintf(stderr, "SCTP shutdown complete\n");
    exit(0);
    break;
  case SCTP_CANT_STR_ASSOC:
    fprintf(stderr, "Error: could not start association\n");
    exit(1);
    break;
  default:
    fprintf(stderr, "Unknown sac_state value: %d", sac->sac_state);
    exit(1);
  }
}

void handle_notification(int srv, union sctp_notification *nf, int sz) {
  switch ( nf->sn_header.sn_type ) {
  case SCTP_ASSOC_CHANGE:
    handle_assoc_change(srv, &nf->sn_assoc_change, sz);
    break;
  case SCTP_STREAM_RESET_EVENT:
    // TODO this should reset the stream and close any connections
    log_printf( "SCTP stream reset\n");
    if ( sz >= sizeof(nf->sn_strreset_event) )
      process_strreset_ack(&nf->sn_strreset_event, sz);
    else
      fprintf(stderr, "handle_notification: not enough space for stream reset event\n");
    break;
  case SCTP_REMOTE_ERROR:
    fprintf(stderr, "SCTP remote error\n");
    break;
  case SCTP_SHUTDOWN_EVENT:
    fprintf(stderr, "SCTP shutdown\n");
    break;
  case SCTP_ADAPTATION_INDICATION:
    fprintf(stderr, "SCTP adaptation indication\n");
    break;
  case SCTP_PARTIAL_DELIVERY_EVENT:
    fprintf(stderr, "SCTP partial delivery\n");
    break;
  default:
    fprintf(stderr, "Unknown SCTP event %d", nf->sn_header.sn_type);
    break;
  }
}

int write_open_app_req(struct wrtcchan *chan, char *app_name, int app_name_len) {
  int cap_len = strlen(g_capability);
  int buf_len = 4 + app_name_len + cap_len;
  void *buf = chan->wrc_buffer;

  if ( buf_len > chan->wrc_buf_sz ) {
    errno = ENOSPC;
    return -1;
  }

  chan->wrc_msg_sz = buf_len;
  *((uint32_t *)buf) = htonl(app_name_len);
  memcpy(buf + 4, app_name, app_name_len);
  memcpy(buf + 4 + app_name_len, g_capability, cap_len);

  return 0;
}

void handle_chan_msg(int srv, struct wrtcchan *chan,
                     void *buf, int sz, int flags) {
  int app_name_len, err, rsp_sz, req;
  struct stkcmsg rsp, *msg = (struct stkcmsg *)buf;
  struct sctp_sndrcvinfo sri;
  struct sockaddr_in endpoint;
  void *data_buf;

  if ( chan->wrc_flags & WRC_DATA_IN_PROG ) {
    req = SCM_REQ_DATA;
    data_buf = msg;
  } else {
    if ( !stkcmsg_has_enough(msg, sz) ) {
      fprintf(stderr, "Invalid control message received: %d %x\n", sz, STK_CMSG_REQ(msg));
      goto reset;
    }
    req = STK_CMSG_REQ(msg);
    data_buf = SCM_DATA(msg);
  }

  chan_sctp_sndrcvinfo(chan, &sri);

  switch ( req ) {
  case SCM_REQ_OPEN_APP:
    if ( WRC_IS_CONTROL(chan) ) {
      app_name_len = ntohl(msg->data.scm_open_app_request.scm_app_len);
      fprintf(stderr, "Request to open app %.*s\n", app_name_len, msg->data.scm_open_app_request.scm_app_id);

      if ( WRC_HAS_MESSAGE_PENDING(chan) ) {
        fprintf(stderr, "Request already in progress on channel %d\n", chan->wrc_chan_id);
        rsp_cmsg_error(srv, chan, STK_CMSG_REQ(msg), STKD_ERROR_SYSTEM_BUSY);
        break;
      }

      err = write_open_app_req(chan, msg->data.scm_open_app_request.scm_app_id, app_name_len);
      if ( err < 0 ) {
        int saved_errno = errno;
        perror("write_open_app_req");
        errno = saved_errno;
        rsp_cmsg_error(srv, chan, STK_CMSG_REQ(msg), STKD_ERROR_SYSTEM_ERROR);
        break;
      }

      chan->wrc_flags |= WRC_ERROR_ON_RETRY | WRC_SCM_IN_PROG;
      chan->wrc_retry_rsp = SCM_REQ_OPEN_APP;
      signal_write_on_chan(chan, OPEN_APP_MAX_RETRIES, 200);
    } else
      goto fault;
    break;
  case SCM_REQ_CONNECT:
    if ( WRC_IS_CONTROL(chan) ) {
      log_printf("Received connect message for %s on %d\n",
                 sk_type_str(msg->data.scm_connect.scm_sk_type),
                 ntohs(msg->data.scm_connect.scm_port));

      if ( chan-> wrc_flags & WRC_HAS_PENDING_CONN ) {
        rsp_sz = SCM_ERROR_RSP_SZ;
        rsp.scm_type = SCM_RESPONSE | SCM_ERROR | SCM_REQ_CONNECT;
        rsp.data.scm_error = htonl(STKD_ERROR_SYSTEM_BUSY);
      } else if ( chan_supports_sk_type(chan, msg->data.scm_connect.scm_sk_type) ) {
        endpoint.sin_family = AF_INET;
        endpoint.sin_port = msg->data.scm_connect.scm_port;

        if ( !get_address_by_descriptor(ntohl(msg->data.scm_connect.scm_app),
                                        &endpoint.sin_addr.s_addr) ) {
          log_printf("Could not find app %d\n", ntohl(msg->data.scm_connect.scm_app));
          rsp_sz = SCM_ERROR_RSP_SZ;
          rsp.scm_type = SCM_RESPONSE | SCM_ERROR | SCM_REQ_CONNECT;
          rsp.data.scm_error = htonl(STKD_ERROR_APP_DOES_NOT_EXIST);
        } else {
          err = mk_socket(msg->data.scm_connect.scm_sk_type);
          if ( err < 0 ) {
            int saved_errno = errno;
            perror("mk_socket");

            rsp_sz = SCM_ERROR_RSP_SZ;
            rsp.scm_type = SCM_RESPONSE | SCM_ERROR | SCM_REQ_CONNECT;
            rsp.data.scm_error = htonl(translate_stk_connection_error(saved_errno));
          } else {
            int old_sk = chan->wrc_sk;

            rsp_sz = 0;

            disarm_channel(chan);
            chan->wrc_sk = err;
            close(old_sk);

            // Attempt to connect on this channel
            err = connect_socket(chan, &endpoint);
            if ( err < 0 ) {
              // TODO we should probably close this socket
              rsp_sz = SCM_ERROR_RSP_SZ;
              rsp.scm_type = SCM_RESPONSE | SCM_ERROR | SCM_REQ_CONNECT;
              rsp.data.scm_error = htonl(translate_stk_connection_error(errno));
            } else {
              if ( err == 0 ) {
                mark_channel_connected(chan);
                arm_channel(chan);

                rsp_sz = SCM_CONNECT_RSP_SZ;
                rsp.scm_type = SCM_RESPONSE | SCM_REQ_CONNECT;
              } else {
                // The connection is in progress
                chan->wrc_family = AF_INET;
                chan->wrc_type = msg->data.scm_connect.scm_sk_type;

                mark_channel_connecting(chan, &endpoint, msg->data.scm_connect.scm_retries);
              }
            }
          }
        }
      } else {
        rsp_sz = SCM_ERROR_RSP_SZ;
        rsp.scm_type = SCM_RESPONSE | SCM_ERROR | SCM_REQ_CONNECT;
        rsp.data.scm_error = htonl(STKD_ERROR_INVALID_SOCKET_TYPE);
      }

      // send the response, if any
      if ( rsp_sz > 0 ) {
        chan_sctp_sndrcvinfo(chan, &sri);
        err = sctp_send(srv, (void *) &rsp, rsp_sz, &sri, 0);
        if ( err < 0 ) {
          perror("SCM_REQ_CONNECT usrsctp_sendv");
          goto reset;
        }

        if ( rsp.scm_type & SCM_ERROR )
          goto reset;
      }
    } else
      goto fault;
    break;
  case SCM_REQ_DATA:
    if ( WRC_IS_CONTROL(chan) ) goto fault;
    else {
      int data_sz, reliable = 0, partial_ok = 0;

      log_printf("Received data message\n");

      switch ( chan->wrc_type ) {
      case SOCK_STREAM:
        if ( chan->wrc_flags & WRC_DATA_IN_PROG )
          data_sz = sz;
        else
          data_sz = sz - SCM_DATA_REQ_SZ;
        reliable = 1;
        partial_ok = 1;
        break;
      case SOCK_DGRAM:
        if ( chan->wrc_flags & WRC_DATA_IN_PROG )
          data_sz = sz;
        else
          data_sz = sz - SCM_DATA_REQ_SZ + 4;
        reliable = 0;
        partial_ok = 0;
        break;
      default:
        log_printf("Can't send data over socket of type: %d(%s)\n",
                   chan->wrc_type, sk_type_str(chan->wrc_type));
        goto done;
      };

      if ( (chan->wrc_msg_sz + data_sz) <= chan->wrc_buf_sz ) {
        uint8_t *outgoing_buf = (unsigned char *) (chan->wrc_buffer + chan->wrc_msg_sz);

        if ( chan->wrc_type == SOCK_DGRAM && (chan->wrc_flags & WRC_DATA_IN_PROG) == 0) {
          // Include frame
          *((uint32_t *) outgoing_buf) = data_sz;
          outgoing_buf += 4;
        }

        memcpy(outgoing_buf, data_buf, data_sz);

        chan->wrc_msg_sz += data_sz;

        if ( (flags & MSG_EOR) || partial_ok ) {
          if ( !(chan->wrc_flags & WRC_HAS_OUTGOING) )
            signal_write_on_chan(chan, 0, 0);
        }

        if ( flags & MSG_EOR ) {
          chan->wrc_flags &= ~WRC_DATA_IN_PROG;
        } else {
          chan->wrc_flags |= WRC_DATA_IN_PROG;
        }

        log_printf("Registered write for channel %d\n", chan->wrc_chan_id);
      } else if ( !reliable ) {
        // TODO we may want to drop the oldest packet
        log_printf("Dropping packet because this channel is not reliable, and the buffer is full\n");
      } else {
        log_printf("Channel %d faulted: not enough space in write buffer\n", chan->wrc_chan_id);
        goto reset;
      }
    }
    break;
  default:
    fprintf(stderr, "Invalid control message type: %d\n", STK_CMSG_REQ(msg));
    goto reset;
  }

 done:

  return;

 fault:
  // A fault is when we receive a control message on a data channel
  // (or a data message on a control channel).
  //
  // This can happen if the channel is not ordered or is not reliable
  //
  // In this case, it's completely harmless
  if ( chan->wrc_ctype == DATA_CHANNEL_RELIABLE ) goto reset;

  log_printf("Out-of-order message received on data channel\n");
  return;

 reset:
  mark_channel_closed(chan);
  return;
}

void handle_msg(int srv,
                struct sctp_sndrcvinfo *rcv,
                void *buf, int sz, int flags) {
  struct wrtcmsg *control;
  struct wrtcchan *chan;
  struct sctp_stream_value ss_prio;
  struct sctp_sndrcvinfo sri;
  wrcchanid chan_id;
  uint8_t ack;
  ssize_t err;
  int sk;
  struct sockaddr_in remote;

  switch ( ntohl(rcv->sinfo_ppid) ) {
  case WEBRTC_BINARY_PPID:
    chan = find_chan(WEBRTC_CHANID(rcv->sinfo_stream));
    if ( !chan ) {
      // Channel does not exist, we should reset the streams
      fprintf(stderr, "Could not find channel: %d\n", WEBRTC_CHANID(rcv->sinfo_stream));
      //reset_wrc_chan(srv, WEBRTC_CHANID(rcv->sinfo_stream));
      break;
    }

    handle_chan_msg(srv, chan, buf, sz, flags);
    break;
  case WEBRTC_CONTROL_PPID:
    control = (struct wrtcmsg *)buf;

    if ( sz < sizeof(control->wm_type) ) break;
    fprintf(stderr, "Received WebRTC control msg\n");

    switch ( control->wm_type ) {
    case WEBRTC_MSG_OPEN:
      chan_id = WEBRTC_CHANID(rcv->sinfo_stream);
      fprintf(stderr, "Request to open WebRTC data channel %d\n", chan_id);

      do_not_close_channel(chan_id);

      chan = alloc_wrtc_chan(chan_id);
      if ( !chan ) {
        fprintf(stderr, "Could not allocate webrtc channel: resetting stream\n");
        //reset_wrc_chan(srv, chan_id);
        break;
      }

      assert(!chan->wrc_pending_reads.next);
      assert(!chan->wrc_closed_stack.next);
      CLEAR_STACK(&chan->wrc_pending_reads);
      CLEAR_STACK(&(chan->wrc_reset_stack));
      CLEAR_STACK(&chan->wrc_closed_stack);

      // All channels start as control channels. Control messages will
      // cause the socket to connect
      chan->wrc_ctype = control->wm_ctype;
      chan->wrc_prio = ntohs(control->wm_prio);
      chan->wrc_rel = ntohl(control->wm_rel);
      chan->wrc_family = 0;
      chan->wrc_type = 0;
      chan->wrc_sk = 0;
      chan->wrc_flags = WRC_CONTROL;
      chan->wrc_buffer = malloc(OUTGOING_BUF_SIZE);
      if ( !chan->wrc_buffer ) {
        fprintf(stderr, "Could not allocate socket buffer\n");
        mark_channel_closed(chan);
        break;
      }
      chan->wrc_buf_sz = OUTGOING_BUF_SIZE;
      chan->wrc_msg_sz = 0;
      chan->wrc_retries_left = 0;
      chan->wrc_retry_interval_millis = 0;
      chan->wrc_retry_rsp = 0;
      if ( clock_gettime(CLOCK_REALTIME, &chan->wrc_last_msg_sent) < 0 ) {
        perror("clock_gettime last_msg_sent");
        mark_channel_closed(chan);
        break;
      }
      if ( clock_gettime(CLOCK_REALTIME, &chan->wrc_created_at) < 0 ) {
        perror("clock_gettime created_at");
        mark_channel_closed(chan);
        break;
      }

      strncpy_fixed(chan->wrc_label, WEBRTC_NAME_MAX,
                    WEBRTC_MSG_LABEL(control), ntohs(control->wm_lbllen));
      chan->wrc_label[MIN(ntohs(control->wm_lbllen), WEBRTC_NAME_MAX - 1)] = '\0';

      strncpy_fixed(chan->wrc_proto, WEBRTC_NAME_MAX, WEBRTC_MSG_PROTO(control),
                    ntohs(control->wm_prolen));
      chan->wrc_proto[MIN(ntohs(control->wm_prolen), WEBRTC_NAME_MAX - 1)] = '\0';

      dbg_chan(chan);

      fprintf(stderr, "Opening WebRTC channel\n");

      chan->wrc_family = AF_INET;
      chan->wrc_type = SOCK_DGRAM;

      sk = socket(AF_INET, SOCK_DGRAM, 0);
      if ( sk < 0 ) {
        perror("socket AF_INET control channel");
        dealloc_wrtc_chan(chan);
        return;
      }

      set_sk_nonblocking(sk);

      remote.sin_family = AF_INET;
      remote.sin_port = htons(STORKD_OPEN_APP_PORT);
      inet_pton(AF_INET, STORKD_ADDR, &remote.sin_addr);
      err = connect(sk, (struct sockaddr *)&remote, sizeof(remote));
      if ( err < 0 ) {
        perror("connect control channel");
      }

      chan->wrc_proxy_buf_sz = 0;
      memset(chan->wrc_proxy_buf, 0, sizeof(chan->wrc_proxy_buf));

      chan->wrc_sk = sk;
      arm_channel(chan);

      ss_prio.assoc_id = g_webrtc_assoc;
      ss_prio.stream_id = WEBRTC_CLIENT_SID(chan_id);
      ss_prio.stream_value = 0xFFFF - control->wm_prio;
      if ( setsockopt(srv, IPPROTO_SCTP, SCTP_STREAM_SCHEDULER_VALUE, &ss_prio, sizeof(ss_prio)) < 0 ) {
        perror("setsockopt SCTP_STREAM_SCHEDULER_VALUE (client)");
      }

      ss_prio.stream_id = WEBRTC_SERVER_SID(chan_id);
      if ( setsockopt(srv, IPPROTO_SCTP, SCTP_STREAM_SCHEDULER_VALUE, &ss_prio, sizeof(ss_prio)) < 0 ) {
        perror("setsockopt SCTP_STREAM_SCHEDULER_VALUE (server)");
      }

      // Send ACK message now
      memset(&sri, 0, sizeof(sri));
      sri.sinfo_stream = WEBRTC_SERVER_SID(chan_id);
      sri.sinfo_ppid = htonl(WEBRTC_CONTROL_PPID);
      sri.sinfo_context = chan_id;
      sri.sinfo_assoc_id = g_webrtc_assoc;

      ack = WEBRTC_MSG_OPEN_ACK;
      err = sctp_send(srv, (void *)&ack, sizeof(ack), &sri, 0);
      if ( err < 0 ) {
        perror("sctp_send WEBRTC_MSG_OPEN_ACK");
        dealloc_wrtc_chan(chan);
        return;
      }

      break;
    default:
      fprintf(stderr, "Unknown WebRTC control message %d\n", control->wm_type);
      break;
    }
    break;
  default:
    fprintf(stderr, "Unknown PPID %d\n", ntohl(rcv->sinfo_ppid));
  }
}

static int receive_sctp(int srv) {
#if WEBRTC_PROXY_DEBUG
  char name[INET_ADDRSTRLEN];
#endif
  char buffer[PROXY_BUF_SIZE];
  struct sockaddr_in addr;
  socklen_t from_len;
  struct sctp_sndrcvinfo rcv_info;
  int flags, n;

  while (1) {
    from_len = sizeof(addr);
    flags = MSG_DONTWAIT;
    log_printf( "webrtc-proxy: going to read from socket\n");
    n = sctp_recvmsg(srv, (void *) &buffer, sizeof(buffer),
                     (struct sockaddr *)&addr, &from_len,
                     (void *) &rcv_info, &flags);

    if ( n < 0 ) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
      else {
        perror("sctp_recvmsg");
        return -1;
      }
    } else if ( n > 0 ) {
      if ( flags & MSG_NOTIFICATION ) {
        union sctp_notification *nf = (union sctp_notification *) buffer;
        log_printf( "Received SCTP notification\n");
        handle_notification(srv, nf, n);
      } else {
        log_printf( "Message of length %llu received from %s:%u on stream %u with SSN %u and TSN %u, PPID %u, complete %d\n",
                   (unsigned long long) n,
                   inet_ntop(AF_INET, &addr.sin_addr, name, sizeof(name)), ntohs(addr.sin_port),
                   rcv_info.sinfo_stream, rcv_info.sinfo_ssn, rcv_info.sinfo_tsn,
                   ntohl(rcv_info.sinfo_ppid), (flags & MSG_EOR) ? 1 : 0);

        handle_msg(srv, &rcv_info, buffer, n, flags);
      }
    }
  }
}

void usage() {
  fprintf(stderr, "webrtc-proxy - WebRTC -> sockets proxy\n");
  fprintf(stderr, "Usage: webrtc-proxy <SCTP UDP port> <capability>\n");
}

int main(int argc, char **argv) {
  uint16_t port;
  //  int on = 1, i = 0;
  int sock;

  struct sctp_event_subscribe subs;
//  struct sctp_event event;
//  uint16_t event_types[] = {
//    SCTP_ASSOC_CHANGE,
//    SCTP_STREAM_RESET_EVENT,
//    SCTP_REMOTE_ERROR,
//    SCTP_SHUTDOWN_EVENT,
//    SCTP_ADAPTATION_INDICATION,
//    SCTP_PARTIAL_DELIVERY_EVENT
//  };

  struct sockaddr_in addr;

  int flags;

  uint8_t kite_sts = 1;
  int comm_up = 0, frag_il = 2;
  //  int autoclose_interval = 60; // Close the association in 60 seconds
  //  struct linger sctp_linger;

  struct sctp_initmsg init;
  struct sctp_assoc_value reseto;

  srand(time(NULL));

  //  sigset_t block;
  if ( fcntl(COMM, F_GETFD) >= 0 ) {
    fprintf(stderr, "webrtc-proxy: running in kite\n");
    comm_up = 1;
  } else {
    fprintf(stderr, "webrtc-proxy: running in debug mode\n");
    comm_up = 0;
  }

  if ( argc < 3 ) {
    usage();
    return 1;
  }

  g_dbg_port = port = atoi(argv[1]);
  g_capability = argv[2];

  memset(g_address_table, 0xFF, sizeof(g_address_table));

  //usrsctp_init(port, NULL, debug_printf);
  //  usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);

  sock = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
  if ( !sock ) {
    perror("socket");
    return 1;
  }

//  if ( setsockopt(sock, SOL_SOCKET, SO_DEBUG, &yes, sizeof(yes)) < 0 ) {
//    perror("setsockopt SO_DEBUG");
//  }

//  if ( setsockopt(sock, IPPROTO_SCTP, SCTP_RECVRCVINFO, &on, sizeof(on)) < 0 ) {
//    perror("setsockopt SCTP_RECVRCVINFO");
//    return 1;
//  }

  g_max_strms = sysconf(_SC_OPEN_MAX);

  init.sinit_num_ostreams   = g_max_strms * 2;
  init.sinit_max_instreams  = g_max_strms * 2;
  init.sinit_max_attempts   = 0;
  init.sinit_max_init_timeo = 0;
  if ( setsockopt(sock, IPPROTO_SCTP, SCTP_INITMSG, &init, sizeof(init)) < 0 ) {
    perror("setsockopt SCTP_INITMSG");
    return 1;
  }

  // Register events
  memset(&subs, 0, sizeof(subs));
  subs.sctp_data_io_event = 1;
  subs.sctp_association_event = 1;
  subs.sctp_address_event = 0;
  subs.sctp_send_failure_event = 1;
  subs.sctp_peer_error_event = 1;
  subs.sctp_shutdown_event = 1;
  subs.sctp_partial_delivery_event = 1;
  subs.sctp_adaptation_layer_event = 0;
  subs.sctp_authentication_event = 0;
  subs.sctp_sender_dry_event = 0;
  subs.sctp_stream_reset_event = 1;
  subs.sctp_assoc_reset_event = 1;
  subs.sctp_stream_change_event = 1;

  if ( setsockopt(sock, IPPROTO_SCTP, SCTP_EVENTS, &subs, sizeof(subs)) < 0 ) {
    perror("setsockopt SCTP_EVENTS");
    return 1;
  }

//  if ( setsockopt(sock, IPPROTO_SCTP, SCTP_AUTOCLOSE, &autoclose_interval, sizeof(autoclose_interval)) < 0 ) {
//    perror("setsockopt SCTP_AUTOCLOSE");
//    return 1;
//  }
//
//  sctp_linger.l_onoff = 1;
//  sctp_linger.l_linger = 0; // Cause the association to shutdown via ABORT
//  if ( setsockopt(sock, SOL_SOCKET, SO_LINGER, &sctp_linger, sizeof(sctp_linger)) < 0 ) {
//    perror("setsockopt SO_LINGER");
//    return 1;
//  }
//
//  memset(&event, 0, sizeof(event));
//  event.se_assoc_id = SCTP_FUTURE_ASSOC;
//  event.se_on = 1;
//  for ( i = 0; i < sizeof(event_types)/sizeof(event_types[0]); ++i ) {
//    event.se_type = event_types[i];
//    if ( usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0 ) {
//      perror("usrsctp_setsockopt SCTP_EVENT");
//    }
//  }

  reseto.assoc_id = 0;
  reseto.assoc_value = 1;
  if ( setsockopt(sock, IPPROTO_SCTP, SCTP_RECONFIG_SUPPORTED, &reseto, sizeof(reseto)) < 0 ) {
    perror("setsockopt SCTP_RECONFIG_SUPPORTED");
    return 1;
  }

  reseto.assoc_id = 0;
  reseto.assoc_value = SCTP_ENABLE_RESET_STREAM_REQ | SCTP_ENABLE_RESET_ASSOC_REQ |
    SCTP_ENABLE_CHANGE_ASSOC_REQ;
  if ( setsockopt(sock, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &reseto, sizeof(reseto)) < 0) {
    perror("setsockopt SCTP_ENABLE_STREAM_RESET");
    return 1;
  }

  if ( setsockopt(sock, IPPROTO_SCTP, SCTP_FRAGMENT_INTERLEAVE, &frag_il, sizeof(frag_il)) < 0 ) {
    perror("setsockopt SCTP_FRAGMENT_INTERLEAVE");
    return 1;
  }

  reseto.assoc_id = 0;
  reseto.assoc_value = 1;
  if ( setsockopt(sock, IPPROTO_SCTP, SCTP_INTERLEAVING_SUPPORTED, &reseto, sizeof(reseto)) < 0 ) {
    perror("setsockopt SCTP_INTERLEAVING_SUPPORTED");
    
    if ( errno != ENOPROTOOPT )
      return 1;
    else
      fprintf(stderr, "webrtc-proxy: running without SCTP interleaving\n");
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port); // TODO accept this port on command line
  addr.sin_addr.s_addr = INADDR_ANY;
  if ( sctp_bindx(sock, (struct sockaddr *) &addr, 1, SCTP_BINDX_ADD_ADDR) < 0 ) {
    perror("sctp_bind");
    return 1;
  }

  if ( listen(sock, 5) < 0 ) {
    perror("listen");
    return 1;
  }

  if ( comm_up ) {
    if ( write(COMM, &kite_sts, 1) != 1 )
      perror("webrtc-proxy: write(COMM)");
    close(COMM);
  }

  flags = fcntl(sock, F_GETFL, 0);
  if ( flags < 0 ) {
    perror("webrtc-proxy: fcntl F_GETFL");
    flags = 0;
  }

  flags = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
  if ( flags < 0 ) {
    perror("webrtc-proxy: fcntl F_SETFL");
    return 1;
  }

  return main_loop(sock);
}
