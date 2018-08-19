#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <storkd_proto.h>

#define SCTP_DEBUG 1
#include <usrsctp.h>

#include "webrtc.h"

#define WEBRTC_PROXY_DEBUG 1

#ifdef WEBRTC_PROXY_DEBUG
#define log_printf(...) fprintf(stderr, __VA_ARGS__)
#else
#define log_printf(...) (void) 0;
#endif

#define SCTP_OUTBOUND_STREAMS 2048

#define WEBRTC_NAME_MAX 128
#define APP_ID_MAX      512

//#define CONTROL_PROTO_NAME "control"
//#define CONTROL_PROTO_LEN  7

typedef uint16_t wrcchanid;
struct wrtcchan {
  pthread_mutex_t wrc_mutex;

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

  char    *wrc_buffer;
  size_t   wrc_buf_sz, wrc_msg_sz;

  // If the WRC_RETRY_MSG flag is set, this is the amount of retries
  // left before giving up
  int      wrc_retries_left;
  int      wrc_retry_interval_millis;

  uint8_t  wrc_retry_rsp;

  struct timespec wrc_last_msg_sent, wrc_created_at;

  uint32_t wrc_flags;
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

#define WEBRTC_CHANID(sid) (sid)
#define WEBRTC_CLIENT_SID(chan_id) (chan_id)
#define WEBRTC_SERVER_SID(chan_id) (chan_id)

// pending connection
struct wrcpendingconn {
  int wpc_sk_type;
  struct sockaddr_in wpc_sin;
};

// Messages that we receive on a control or data socket
struct stkcmsg {
  uint8_t scm_type;
  union {
    struct {
      uint32_t scm_app_len;
      char scm_app_id[];
    } scm_open_app_request;
    struct {
      uint8_t scm_retries;
      uint8_t scm_sk_type;
      uint16_t scm_port;
      uint32_t scm_app;
    } scm_connect;
    uint32_t scm_opened_app;
    uint32_t scm_error;
    char scm_data; // Use with & to get the address of the first character
  } data;
} __attribute__ ((packed));

#define STK_CMSG_REQ(msg) ((msg)->scm_type & SCM_REQ_MASK)
#define STK_CMSG_IS_RSP(msg) ((msg)->scm_type & SCM_RESPONSE)

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

#define STORKD_ADDR "10.0.0.1"
#define STORKD_OPEN_APP_PORT 9998 // The port where we send open app requests

#define OUTGOING_BUF_SIZE    8192
#define PROXY_BUF_SIZE 65536
#define OPEN_APP_MAX_RETRIES 7
#define MAX_EPOLL_EVENTS     16
#define ADDR_DESC_TBL_SZ     1024
#define DFL_EPOLL_EVENTS     (EPOLLIN | EPOLLRDHUP | EPOLLPRI | EPOLLONESHOT)

// Global state

const char *g_capability = NULL;

sctp_assoc_t g_webrtc_assoc = SCTP_FUTURE_ASSOC;
int g_max_strms = 1024;
int g_num_strms = 1024;

pthread_mutex_t g_channel_mutex = PTHREAD_MUTEX_INITIALIZER;
struct wrtcchan *g_channels = NULL;
struct wrtcchan **g_channel_htbl = NULL;
int g_channels_open = 0;

pthread_mutex_t g_addresses_mutex = PTHREAD_MUTEX_INITIALIZER;
uint32_t g_address_table[ADDR_DESC_TBL_SZ];
int g_address_next_desc = 0;

int g_epollfd;
pthread_barrier_t g_epoll_barrier;
pthread_t g_epoll_thread;

// Utilities
void
debug_printf(const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  vfprintf(stderr, format, ap);
  va_end(ap);
}

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

int translate_stk_connection_error(int which) {
  switch ( which ) {
  case ENOENT:       return STKD_ERROR_INVALID_ADDR;
  case ENETUNREACH:
  case ECONNREFUSED: return STKD_ERROR_CONN_REFUSED;
  case EALREADY:     return STKD_ERROR_SYSTEM_BUSY;
  case ETIMEDOUT:    return STKD_ERROR_TEMP_UNAVAILABLE;
  default:           return STKD_ERROR_SYSTEM_ERROR;
  }
}

int mk_socket(int sk_type, struct sockaddr_in *sin ) {
  int sk, err;
  char name[INET6_ADDRSTRLEN];

  sk = socket(AF_INET, sk_type, 0);
  if ( sk < 0 ) {
    perror("mk_socket: socket");
    return -1;
  }

  log_printf("Will connect to %s:%d\n",
             inet_ntop(AF_INET, &sin->sin_addr, name, sizeof(name)),
             ntohs(sin->sin_port));
  err = connect(sk, (struct sockaddr *) sin, sizeof(*sin));
  if ( err < 0 ) {
    perror("mk_socket: connect");
    close(sk);
    return -1;
  }

  return sk;
}

// address utilities
int get_address_descriptor(uint32_t ip) {
  int i = 0, ret = -1;
  if ( pthread_mutex_lock(&g_addresses_mutex) != 0 ) return -1;

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
  pthread_mutex_unlock(&g_addresses_mutex);
  return ret;
}

int get_address_by_descriptor(int desc, uint32_t *ip) {
  int ret;

  if ( pthread_mutex_lock(&g_addresses_mutex) != 0 ) return 0;

  if ( desc < g_address_next_desc ) {
    ret = 1;
    *ip = g_address_table[desc];
  } else
    ret = 0;

  pthread_mutex_unlock(&g_addresses_mutex);
  return ret;
}

// channel utilities

inline uint8_t get_chan_sts(struct wrtcchan *c) {
  return __atomic_load_n(&c->wrc_sts, __ATOMIC_CONSUME);
}

inline void set_chan_sts(struct wrtcchan *c, uint8_t newsts) {
  __atomic_store_n(&c->wrc_sts, newsts, __ATOMIC_SEQ_CST);
}

inline void lock_channel(struct wrtcchan *c) {
  int err = pthread_mutex_lock(&c->wrc_mutex);
  if ( err != 0 ) {
    fprintf(stderr, "Could not lock mutex: %s\n", strerror(err));
    exit(1);
  }
}

inline void release_channel(struct wrtcchan *c) {
  int err = pthread_mutex_unlock(&c->wrc_mutex);
  if ( err != 0 ) {
    fprintf(stderr, "Could not release mutex: %s\n", strerror(err));
    exit(1);
  }
}

char *strncpy_fixed(char *dst, size_t dstlen, char *src, size_t srclen) {
  if ( srclen < dstlen ) {
    memcpy(dst, src, srclen);
    dst[srclen] = '\0';
  } else {
    memcpy(dst, src, dstlen - 1);
    dst[dstlen - 1] = '\0';
  }

  return dst;
}

void insert_chan_in_htbl(struct wrtcchan *c) {
  int hidx = c->wrc_chan_id % g_num_strms;
  for ( ; g_channel_htbl[hidx]; hidx ++ );
  g_channel_htbl[hidx] = c;
}

struct wrtcchan *find_chan(wrcchanid cid) {
  int hidx, first_idx, scan_count;
  struct wrtcchan *ret;

  if ( pthread_mutex_lock(&g_channel_mutex) != 0 ) return NULL;

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

  pthread_mutex_unlock(&g_channel_mutex);

  return ret;
}

void remove_chan_from_tbl(struct wrtcchan *c) {
  int hidx = c->wrc_chan_id % g_num_strms, jidx, kidx;

  // TODO test this
  if ( g_channel_htbl[hidx] ) {
    jidx = hidx;

    while ( 1 ) {
      g_channel_htbl[hidx] = NULL;

      do {
        jidx = (jidx + 1) % g_num_strms;

        if ( !g_channel_htbl[jidx] ) break;

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

  if ( pthread_mutex_lock(&g_channel_mutex) != 0 ) return NULL;

  for ( i = 0; i < g_num_strms; ++i ) {
    if ( get_chan_sts(&g_channels[i]) == WEBRTC_STS_INVALID ) {
      if ( pthread_mutex_init(&g_channels[i].wrc_mutex, NULL) != 0 ) goto done;
      lock_channel(&g_channels[i]);

      g_channels[i].wrc_sts = WEBRTC_STS_VALID;
      g_channels[i].wrc_chan_id = chan_id;
      memset(&g_channels[i].wrc_label, WEBRTC_NAME_MAX, 0);
      memset(&g_channels[i].wrc_proto, WEBRTC_NAME_MAX, 0);
      g_channels[i].wrc_family = 0;
      g_channels[i].wrc_type = 0;
      g_channels[i].wrc_sk = 0;

      insert_chan_in_htbl(&g_channels[i]);

      ret = &g_channels[i];
      goto done;
    }
  }

 done:
  pthread_mutex_unlock(&g_channel_mutex);
  return ret;
}

void dealloc_wrtc_chan(struct wrtcchan *chan) {
  if ( pthread_mutex_lock(&g_channel_mutex) != 0 ) return;

  remove_chan_from_tbl(chan);

  pthread_mutex_unlock(&g_channel_mutex);

  lock_channel(chan);
  chan->wrc_sts = WEBRTC_STS_INVALID;

  if ( chan->wrc_sk )
    close(chan->wrc_sk);

  if ( chan->wrc_buffer ) {
    free(chan->wrc_buffer);
    chan->wrc_buffer = NULL;
  }
  release_channel(chan);

  if ( pthread_mutex_destroy(&chan->wrc_mutex) != 0 ) {
    fprintf(stderr, "Could not destroy channel mutex\n");
  }
}

void rsp_cmsg_error(struct socket *srv, struct wrtcchan *chan, uint8_t req, int rsperr) {
  struct stkcmsg msg;
  struct sctp_sndinfo si;
  int err;

  msg.scm_type = req | SCM_RESPONSE | SCM_ERROR;
  msg.data.scm_error = htonl(rsperr);

  si.snd_sid = WEBRTC_SERVER_SID(chan->wrc_chan_id);
  si.snd_flags = 0;
  si.snd_ppid = htonl(WEBRTC_BINARY_PPID);
  si.snd_context = chan->wrc_chan_id;
  si.snd_assoc_id = g_webrtc_assoc;

  err = usrsctp_sendv(srv, (void *)&msg, sizeof(msg), NULL, 0,
                      (void *) &si, sizeof(si),
                      SCTP_SENDV_SNDINFO, 0);
  if ( err < 0 ) {
    perror("send_cmsg_error: usrsctp_sendv");
    // TODO close the channel or something
  }
}

void reset_wrc_chan(struct socket *srv, wrcchanid chan_id) {
  struct {
    struct sctp_reset_streams sctp;
    uint16_t strms[2];
  } rst;

  rst.sctp.srs_assoc_id = g_webrtc_assoc;
  rst.sctp.srs_flags = SCTP_STREAM_RESET_INCOMING | SCTP_STREAM_RESET_OUTGOING;
  rst.sctp.srs_number_streams = 2;
  rst.sctp.srs_stream_list[0] = WEBRTC_CLIENT_SID(chan_id);
  rst.sctp.srs_stream_list[1] = WEBRTC_SERVER_SID(chan_id);

  if ( usrsctp_setsockopt(srv, IPPROTO_SCTP, SCTP_RESET_STREAMS, &rst, sizeof(rst)) < 0 ) {
    perror("usrsctp_setsockopt SCTP_RESET_STREAMS");
  }
}

void wait_for_write_on_chan(struct wrtcchan *chan) {
  struct epoll_event ev;
  int err;

  ev.events = DFL_EPOLL_EVENTS | EPOLLOUT;
  ev.data.ptr = (void *) chan;

  err = epoll_ctl(g_epollfd, EPOLL_CTL_MOD, chan->wrc_sk, &ev);
  if ( err == -1 ) {
    perror("epoll_ctl EPOLL_CTL_MOD");
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
  int err = pthread_kill(g_epoll_thread, SIGUSR1);
  if ( err != 0 ) {
    errno = err;
    perror("pthread_kill SIGUSR1");
  }

  log_printf("Signaled timeout\n");
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
    perror("epoll_ctl EPOLL_CTL_ADD");
  }
}

void mark_channel_open(struct wrtcchan *chan, int new_sk) {
  int old_sk;

  // Close the control socket, and unset the flag
  chan->wrc_sts = WEBRTC_STS_OPEN; // The open status signifies that we are connecting
  chan->wrc_flags &= ~(WRC_CONTROL | WRC_HAS_PENDING_CONN | WRC_RETRY_MSG);
  chan->wrc_msg_sz = 0;
  chan->wrc_retries_left = 0;

  disarm_channel(chan);

  old_sk = chan->wrc_sk;
  chan->wrc_sk = new_sk;
  close(old_sk);

  mark_channel_writable(chan, 0, 0);
  arm_channel(chan);
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

  err = epoll_ctl(g_epollfd, EPOLL_CTL_MOD, chan->wrc_sk, &ev);
  if ( err == -1 ) {
    perror("cancel_pending_writes: epoll_ctl");
  }
}

void chan_sctp_sndinfo(struct wrtcchan *chan, struct sctp_sndinfo *si) {
  si->snd_sid = WEBRTC_SERVER_SID(chan->wrc_chan_id);
  si->snd_flags = 0;
  si->snd_ppid = htonl(WEBRTC_BINARY_PPID);
  si->snd_context = chan->wrc_chan_id;
  si->snd_assoc_id = g_webrtc_assoc;
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

void dbg_chan(struct wrtcchan *chan) {
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
}

void dbg_assoc_change(struct sctp_assoc_change *sac, int sz) {
  int ft_cnt = sz - sizeof(*sac), i;
  uint8_t *fts = (uint8_t *) sac->sac_info;
  fprintf(stderr, "SCTP Association change:\n");
  fprintf(stderr, "  - Num outbound: %d\n", sac->sac_outbound_streams);
  fprintf(stderr, "  -  Num inbound: %d\n", sac->sac_inbound_streams);
  fprintf(stderr, "  -     Assoc ID: %d\n", sac->sac_assoc_id);
  fprintf(stderr, "  -     Supports: ");

  for ( i = 0; i < ft_cnt; ++i )
    switch ( fts[i] ) {
    case SCTP_ASSOC_SUPPORTS_PR:
      fprintf(stderr, "Partial reliability; ");
      break;
    case SCTP_ASSOC_SUPPORTS_AUTH:
      fprintf(stderr, "Auth; ");
      break;
    case SCTP_ASSOC_SUPPORTS_ASCONF:
      fprintf(stderr, "ASCONF; ");
      break;
    case SCTP_ASSOC_SUPPORTS_MULTIBUF:
      fprintf(stderr, "Multibuf; ");
      break;
    case  SCTP_ASSOC_SUPPORTS_RE_CONFIG:
      fprintf(stderr, "Reconfig; ");
      break;
    default: break;
    }
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

      return sz <= (SCM_OPEN_APP_REQ_SZ_MIN + appnmlen);
    }
  case SCM_REQ_CONNECT:
    if ( STK_CMSG_IS_RSP(msg) )
      return sz <= SCM_CONNECT_RSP_SZ;
    else
      return sz <= SCM_CONNECT_REQ_SZ;
  case SCM_REQ_DATA:
  default:
    return sz <= sizeof(*msg);
  }
}

// proxy_buf is of size PROXY_BUF_SIZE
void proxy_data(struct socket *srv, struct wrtcchan *chan, char *proxy_buf) {
  char addr_buf[INET6_ADDRSTRLEN]; // For forwards compatibility

  struct sctp_sndinfo si;
  int err, rsp_sz;

  chan_sctp_sndinfo(chan, &si);

  err = recv(chan->wrc_sk, proxy_buf, PROXY_BUF_SIZE, 0);
  if ( err < 0 ) {
    perror("proxy_data recv");
    return;
  }

  if ( chan->wrc_flags & WRC_CONTROL ) {
    struct stkdmsg *msg = (struct stkdmsg *) proxy_buf;
    struct stkcmsg rsp;
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
              rsp.data.scm_error = STKD_ERROR_NO_SPACE;
              rsp_sz = SCM_ERROR_RSP_SZ;
            } else {
              rsp.data.scm_opened_app = err;
            }
          }

          // Because the message was responded to, we can clear out
          // any pending writes
          //
          // Note, that the epoll event loop may still wake up for
          // this, but it will notice that nothing is present in the
          // output buffer and it will wait.
          cancel_pending_writes(chan);

          err = usrsctp_sendv(srv, (void *) &rsp, rsp_sz, NULL, 0,
                              (void *) &si, sizeof(si),
                              SCTP_SENDV_SNDINFO, 0);
          if ( err < 0 ) {
            perror("proxy_data(cmsg): usrsctp_sendv");
            // TODO close the channel or something
          }
          break;
        default:
          log_printf("Unknown storkd request type: %d\n", STKD_REQ(msg));
        }
      } else {
        log_printf("Got request from storkd (TODO)\n");
      }
    } else {
      log_printf("Not enough data in storkd response\n");
    }
  } else {

    // TODO use the WRC_HAS_OUTGOING mechanism

    // Now send the data over the usrsctp socket
    err = usrsctp_sendv(srv, (void *) proxy_buf, err, NULL, 0,
                        (void *) &si, sizeof(si),
                        SCTP_SENDV_SNDINFO, 0);
    if ( err < 0 ) {
      perror("proxy_data: usrsctp_sendv");
      // TODO close the channel or something
    }

  }
}

void send_connection_opens_rsp(struct socket *srv, struct wrtcchan *chan) {
  struct stkcmsg rsp;
  struct sctp_sndinfo si;
  int err;

  rsp.scm_type = SCM_RESPONSE | SCM_REQ_CONNECT;

  chan_sctp_sndinfo(chan, &si);

  err = usrsctp_sendv(srv, (void *)&rsp, SCM_CONNECT_RSP_SZ, NULL, 0,
                      (void *)&si, sizeof(si), SCTP_SENDV_SNDINFO, 0);
  if ( err < 0 ) {
    perror("send_connection_opens_rsp: usrsctp_sendv");
    // TODO close the channel?
  }
}

void flush_chan(struct socket *srv, struct wrtcchan *chan, int *new_events) {
  int err;

  if ( chan->wrc_flags & WRC_HAS_PENDING_CONN ) {
    struct wrcpendingconn *pconn = (struct wrcpendingconn *) chan->wrc_buffer;

    log_printf("Reattempting connection on channel %d\n", chan->wrc_chan_id);
    assert(chan->wrc_msg_sz == sizeof(struct wrcpendingconn));

    err = mk_socket(pconn->wpc_sk_type, &pconn->wpc_sin);
    if ( err < 0 ) {
      int scm_error;
      perror("mk_socket");

      scm_error = translate_stk_connection_error(errno);

      chan->wrc_retries_left--;
      if ( chan->wrc_retries_left > 0 ) {
        log_printf("Retrying connection on %d\n", chan->wrc_chan_id);
        chan->wrc_retry_interval_millis *= 2;
      } else {
        rsp_cmsg_error(srv, chan, SCM_REQ_CONNECT, scm_error);
        chan->wrc_flags &= ~(WRC_RETRY_MSG | WRC_HAS_PENDING_CONN);
      }
    } else {
      log_printf("Successfully opened channel %d\n", chan->wrc_chan_id);
      chan->wrc_type = pconn->wpc_sk_type;
      mark_channel_open(chan, err);
    }
  } else if ( chan->wrc_flags & WRC_HAS_OUTGOING ) {
    log_printf("Flushing channel %d of type %s\n", chan->wrc_chan_id, sk_type_str(chan->wrc_type));

    if ( chan->wrc_msg_sz == 0 ) {
      // If there is no message, we are only doing this for the state
      // transitions. Return immmediately
      //
      // TODO do we need empty data grams??

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

        chan->wrc_retries_left--;
        if ( chan->wrc_retries_left == 0 ) {
          chan->wrc_msg_sz = 0;
          log_printf("No more retries left for datagram\n");
          if ( chan->wrc_flags & WRC_ERROR_ON_RETRY ) {
            log_printf("An error was requested to be delivered on retry failure\n");
            rsp_cmsg_error(srv, chan, chan->wrc_retry_rsp, STKD_ERROR_TEMP_UNAVAILABLE);
          }
          chan->wrc_flags &= ~(WRC_RETRY_MSG | WRC_ERROR_ON_RETRY);
        } else {
          chan->wrc_retry_interval_millis *= 2;
        }
      } else
        chan->wrc_msg_sz = 0;
      break;
    case SOCK_STREAM:
      // Retries are ignored on SOCK_STREAM
      chan->wrc_retries_left = 0;
      chan->wrc_flags &= ~(WRC_RETRY_MSG | WRC_ERROR_ON_RETRY);

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

void state_transition(struct socket *srv, struct wrtcchan *chan, int epev) {
  // Perform necessary transitions
  if ( chan->wrc_sts == WEBRTC_STS_OPEN && (epev & (EPOLLIN | EPOLLOUT)) ) {
    log_printf("Marking cannel %d as connected\n", chan->wrc_chan_id);
    chan->wrc_sts == WEBRTC_STS_CONNECTED;
    chan->wrc_flags |= 0;

    // Typically, we want to send some kind of success msg here as well
    send_connection_opens_rsp(srv, chan);
  }
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
      log_printf("channel retry interval is %d\n", chan->wrc_retry_interval_millis);
      timespec_add(&when, &chan->wrc_last_msg_sent, &ri);

      log_printf("comparing times (%lu,%lu) < (%lu, %lu)\n", now->tv_sec, now->tv_nsec, when.tv_sec, when.tv_nsec);

      if ( timespec_lt(&when, now) ) {
        // If the time to retry is less than now, we need to retry
        chan->wrc_flags |= WRC_HAS_OUTGOING;
        return 1;
      } else {
        // Approximate how much time we need to wait until this needs a retry
        int timeout_millis;
        timeout_millis = (when.tv_sec * 1000 + (when.tv_nsec / 1000000));
        timeout_millis -= (now->tv_sec * 1000 + (now->tv_nsec / 1000000));

        *timeout = UPDATE_TIMEOUT(*timeout, timeout_millis);

        return 0;
      }
    }
  } else
    return 0;
}

void sigusr1_handler(int s) {
  write(STDERR_FILENO, "SIGUSR1 Received\n", 17);
}

void *epoll_thread(void *srv_raw) {
  char proxy_buf[PROXY_BUF_SIZE];

  struct socket *srv = (struct socket *) srv_raw;
  struct epoll_event evs[MAX_EPOLL_EVENTS];
  int i, ev_cnt = 0, timeout = -1, err;
  struct timespec now;
  sigset_t block, old;
  struct sigaction sig;

  fprintf(stderr, "WebRTC epoll thread starts\n");

  sigfillset(&block);
  err = pthread_sigmask(SIG_SETMASK, &block, &old);
  if ( err != 0 ) {
    errno = err;
    perror("pthread_sigmask SIG_SETMASK");
    exit(20);
  }

  sigdelset(&old, SIGUSR1); // Make sure sigusr1 is unblocked

  // Set sigusr1 to ignore
  sig.sa_handler = sigusr1_handler; // SIG_IGN;
  sigfillset(&sig.sa_mask);
  sigdelset(&sig.sa_mask, SIGSEGV);
  sigdelset(&sig.sa_mask, SIGTERM);
  sig.sa_flags = SA_RESTART;
  err = sigaction(SIGUSR1, &sig, NULL);
  if ( err < 0 ) {
    perror("sigaction SIGUSR1");
    exit(21);
  }

  g_epollfd = epoll_create1(EPOLL_CLOEXEC);
  if ( g_epollfd < 0 ) {
    perror("epoll_create1");
    exit(4);
  }
  pthread_barrier_wait(&g_epoll_barrier);

  // Add the event fd
  if ( pthread_mutex_lock(&g_channel_mutex) != 0 ) exit(5);
  for ( i = 0; i < g_num_strms; ++i )
    if ( g_channel_htbl[i] ) {
      lock_channel(g_channel_htbl[i]);
      arm_channel(g_channel_htbl[i]);
      release_channel(g_channel_htbl[i]);
    }
  pthread_mutex_unlock(&g_channel_mutex);

  while (1) {
    ev_cnt = epoll_pwait(g_epollfd, evs, MAX_EPOLL_EVENTS, timeout, &old);
    if ( ev_cnt == -1 ) {
      if ( errno == EINTR ) {
        // An interrupt may have caused something to change, so we
        // should proceed as usual
        log_printf("Received EPOLL interrupt\n");
        ev_cnt = 0;
      } else {
        perror("epoll_wait");
        exit(6);
      }
    }
    log_printf("Finished epoll wait: %d\n", ev_cnt);

    timeout = -1;

    // Go over each event in the epoll and continue
    for ( i = 0; i < ev_cnt; ++i ) {
      struct epoll_event *ev = evs + i;
      struct wrtcchan *chan = (struct wrtcchan *) ev->data.ptr;
      int new_events = EPOLLIN | EPOLLRDHUP | EPOLLPRI | EPOLLONESHOT;
      int chan_sk;

      lock_channel(chan);

      log_printf("Got epoll for %d %d\n", chan->wrc_chan_id, ev->events);

      state_transition(srv, chan, ev->events);

      if ( ev->events & EPOLLIN )
        // We have data ready for reading. Read the data and send it
        // out on the channel.
        proxy_data(srv, chan, proxy_buf);

      if ( ev->events & EPOLLOUT )
        // The socket can be written to. Flush any pending messages
        flush_chan(srv, chan, &new_events);

      if ( ev->events & EPOLLRDHUP ) {
        wrcchanid chan_id = chan->wrc_chan_id;

        // The channel was closed
        release_channel(chan);

        dealloc_wrtc_chan(chan);
        reset_wrc_chan(srv, chan_id);
      } else {
        // Rearm the channel
        release_channel(chan);

        ev->events = new_events;
        err = epoll_ctl(g_epollfd, EPOLL_CTL_MOD, chan->wrc_sk, ev);
        if ( err < 0 ) {
          perror("epoll_ctl EPOLL_CTL_MOD");
        }
      }
    }

    // Now, go over all open channels and if a timeout has expired,
    // mark the socket as waiting for output as well
    pthread_mutex_lock(&g_channel_mutex);
    if ( clock_gettime(CLOCK_REALTIME, &now) < 0 ) {
      perror("clock_gettime now");
      exit(10);
    }

    for ( i = 0, timeout = -1; i < g_num_strms; ++i )
      if ( g_channel_htbl[i] ) {
        if ( chan_needs_retry(g_channel_htbl[i], &now, &timeout) ) {
          lock_channel(g_channel_htbl[i]);
          log_printf("WebRTC channel is requesting retry %d\n", g_channel_htbl[i]->wrc_chan_id);
          wait_for_write_on_chan(g_channel_htbl[i]);
          release_channel(g_channel_htbl[i]);
        }
      }
    pthread_mutex_unlock(&g_channel_mutex);
  }
}

// SCTP Server

void warn_if_ext_not_supported(struct sctp_assoc_change *sac, int sz, const char *nm, uint8_t which) {
  int ft_cnt = sz - sizeof(*sac), i;
  uint8_t *fts = (uint8_t *) sac->sac_info;
  for ( i = 0; i < ft_cnt; ++i ) {
    if ( fts[i] == which ) return;
  }

  fprintf(stderr, "Association does not support %s\n", nm);
}

void handle_assoc_change(struct socket *srv, struct sctp_assoc_change *sac, int sz) {
  int err;

  if ( sz < sizeof(*sac) ) return;

  switch ( sac->sac_state ) {
  case SCTP_COMM_UP:
    dbg_assoc_change(sac, sz);
    if ( g_webrtc_assoc != SCTP_FUTURE_ASSOC ) {
      struct socket *assoc;
      // Close this association
      fprintf(stderr, "Received another association: %d\n", sac->sac_assoc_id);
      assoc = usrsctp_peeloff(srv, sac->sac_assoc_id);
      if ( !assoc ) {
        perror("usrsctp_peeloff");
        return;
      }

      if ( usrsctp_shutdown(assoc, SHUT_RDWR) < 0 ) {
        perror("usrsctp_shutdown");
        return;
      }
    } else {
      struct sctp_assoc_value sched;

      g_webrtc_assoc = sac->sac_assoc_id;
      warn_if_ext_not_supported(sac, sz, "SCTP reconfig", SCTP_ASSOC_SUPPORTS_RE_CONFIG);
      warn_if_ext_not_supported(sac, sz, "SCTP partial reliability", SCTP_ASSOC_SUPPORTS_PR);

      sched.assoc_id = g_webrtc_assoc;
      sched.assoc_value = SCTP_SS_PRIORITY;
      if ( usrsctp_setsockopt(srv, IPPROTO_SCTP, SCTP_PLUGGABLE_SS, &sched, sizeof(sched)) < 0 ) {
        perror("usrsctp_setsockopt SCTP_PLUGGABLE_SS");
      }

      g_num_strms = (sac->sac_outbound_streams < sac->sac_inbound_streams ?
                     sac->sac_inbound_streams : sac->sac_outbound_streams);
      g_channels = calloc(sizeof(*g_channels), g_num_strms);
      if ( !g_channels ) {
        perror("calloc");
        exit(200);
      }

      g_channel_htbl = calloc(sizeof(*g_channel_htbl), g_num_strms);
      if ( !g_channel_htbl ) {
        perror("calloc");
        exit(201);
      }

      // Launch proxy thread
      err = pthread_barrier_init(&g_epoll_barrier, NULL, 2);
      if ( err != 0 ) {
        errno = err;
        perror("pthread_barrier_init");
        exit(3);
      }

      err = pthread_create(&g_epoll_thread, NULL,
                           epoll_thread, (void *) srv);
      if ( err != 0 ) {
        errno = err;
        perror("pthread_create");
        exit(3);
      }

      pthread_barrier_wait(&g_epoll_barrier);
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

void handle_notification(struct socket *srv, union sctp_notification *nf, int sz) {
  switch ( nf->sn_header.sn_type ) {
  case SCTP_ASSOC_CHANGE:
    handle_assoc_change(srv, &nf->sn_assoc_change, sz);
    break;
  case SCTP_STREAM_RESET_EVENT:
    // TODO this should reset the stream and close any connections
    fprintf(stderr, "SCTP stream reset\n");
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
}

int do_connect(struct stkcmsg *msg, struct sockaddr_in *sin) {

  sin->sin_family = AF_INET;
  sin->sin_port = msg->data.scm_connect.scm_port;

  if ( !get_address_by_descriptor(ntohl(msg->data.scm_connect.scm_app), &sin->sin_addr.s_addr) ) {
    errno = ENOENT;
    return -1;
  }

  return mk_socket(msg->data.scm_connect.scm_sk_type, sin);
}

void handle_chan_msg(struct socket *srv, struct wrtcchan *chan,
                     void *buf, int sz) {
  int app_name_len, send_buf_len, err, rsp_sz;
  struct stkcmsg rsp, *msg = (struct stkcmsg *)buf;
  struct sctp_sndinfo si;
  struct sockaddr_in endpoint;

  lock_channel(chan);

  if ( !stkcmsg_has_enough(msg, sz) ) {
    fprintf(stderr, "Invalid control message received\n");
    goto reset;
  }

  chan_sctp_sndinfo(chan, &si);

  switch ( STK_CMSG_REQ(msg) ) {
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
        rsp_cmsg_error(srv, chan, STK_CMSG_REQ(msg), STKD_ERROR_SYSTEM_ERROR);
        break;
      }

      chan->wrc_flags |= WRC_ERROR_ON_RETRY;
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
        rsp.data.scm_error = STKD_ERROR_SYSTEM_BUSY;
      } else if ( chan_supports_sk_type(chan, msg->data.scm_connect.scm_sk_type) ) {
        err = do_connect(msg, &endpoint);
        if ( err < 0 ) {
          struct wrcpendingconn *pconn = (struct wrcpendingconn *) chan->wrc_buffer;
          int saved_errno = errno;
          perror("do_connect");

          rsp_sz = SCM_ERROR_RSP_SZ;
          rsp.scm_type = SCM_RESPONSE | SCM_ERROR | SCM_REQ_CONNECT;

          rsp.data.scm_error = translate_stk_connection_error(saved_errno);

          // If the error is something that may change in the future,
          // check if we want to retry
          if ( STKD_ERR_IS_TEMPORARY(rsp.data.scm_error) &&
               msg->data.scm_connect.scm_retries > 0 ) {
            log_printf("Retrying connection\n");

            // We will want to retry this
            rsp_sz = 0;
            chan->wrc_sts = WEBRTC_STS_VALID;    // We are in the process of connecting
            chan->wrc_flags |= WRC_RETRY_MSG | WRC_HAS_PENDING_CONN; // Wait until we are ready to connect
            chan->wrc_retries_left = msg->data.scm_connect.scm_retries;
            chan->wrc_retry_interval_millis = 100;

            chan->wrc_msg_sz = sizeof(*pconn);
            pconn->wpc_sk_type = msg->data.scm_connect.scm_sk_type;
            memcpy(&pconn->wpc_sin, &endpoint, sizeof(endpoint));

            signal_new_timeout();
          }
        } else {
          chan->wrc_family = AF_INET;
          chan->wrc_type = msg->data.scm_connect.scm_sk_type;

          mark_channel_open(chan, err);

          rsp_sz = 0;

          // The response will be sent by the runtime
        }
      } else {
        rsp_sz = SCM_ERROR_RSP_SZ;
        rsp.scm_type = SCM_RESPONSE | SCM_ERROR | SCM_REQ_CONNECT;
        rsp.data.scm_error = STKD_ERROR_INVALID_SOCKET_TYPE;
      }

      // send the response, if any
      if ( rsp_sz > 0 ) {
        chan_sctp_sndinfo(chan, &si);
        err = usrsctp_sendv(srv, (void *) &rsp, rsp_sz, NULL, 0,
                            (void *) &si, sizeof(si),
                            SCTP_SENDV_SNDINFO, 0);
        if ( err < 0 ) {
          perror("SCM_REQ_CONNECT usrsctp_sendv");
          goto reset;
        }
      }
    } else
      goto fault;
    break;
  case SCM_REQ_DATA:
    if ( WRC_IS_CONTROL(chan) ) goto fault;
    else {
      log_printf("Received data message\n");
    }
    break;
  default:
    fprintf(stderr, "Invalid control message type: %d\n", STK_CMSG_REQ(msg));
    goto reset;
  }

  release_channel(chan);
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
  release_channel(chan);
  return;

 reset:
  reset_wrc_chan(srv, chan->wrc_chan_id);
  release_channel(chan);
  dealloc_wrtc_chan(chan);
  return;
}

void handle_msg(struct socket *srv,
                struct sctp_rcvinfo *rcv, int rcv_sz,
                void *buf, int sz) {
  struct wrtcmsg *control;
  struct wrtcchan *chan;
  struct sctp_stream_value ss_prio;
  struct sctp_sndinfo si;
  wrcchanid chan_id;
  uint8_t ack;
  ssize_t err;
  int sk;
  struct sockaddr_in remote;

  switch ( ntohl(rcv->rcv_ppid) ) {
  case WEBRTC_BINARY_PPID:
    chan = find_chan(WEBRTC_CHANID(rcv->rcv_sid));
    if ( !chan ) {
      // Channel does not exist, we should reset the streams
      fprintf(stderr, "Could not find channel: %d\n", WEBRTC_CHANID(rcv->rcv_sid));
      reset_wrc_chan(srv, chan_id);
      break;
    }

    // If we find the channel, lock it
    handle_chan_msg(srv, chan, buf, sz);
    break;
  case WEBRTC_CONTROL_PPID:
    control = (struct wrtcmsg *)buf;

    if ( sz < sizeof(control->wm_type) ) break;
    fprintf(stderr, "Received WebRTC control msg\n");

    switch ( control->wm_type ) {
    case WEBRTC_MSG_OPEN:
      chan_id = WEBRTC_CHANID(rcv->rcv_sid);
      fprintf(stderr, "Request to open WebRTC data channel %d\n", chan_id);

      chan = alloc_wrtc_chan(chan_id);
      if ( !chan ) {
        fprintf(stderr, "Could not allocate webrtc channel: resetting stream\n");
        reset_wrc_chan(srv, chan_id);
        break;
      }

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
        reset_wrc_chan(srv, chan_id);
        break;
      }
      chan->wrc_buf_sz = OUTGOING_BUF_SIZE;
      chan->wrc_msg_sz = 0;
      chan->wrc_retries_left = 0;
      chan->wrc_retry_interval_millis = 0;
      chan->wrc_retry_rsp = 0;
      if ( clock_gettime(CLOCK_REALTIME, &chan->wrc_last_msg_sent) < 0 ) {
        perror("clock_gettime last_msg_sent");
        reset_wrc_chan(srv, chan_id);
        break;
      }
      if ( clock_gettime(CLOCK_REALTIME, &chan->wrc_created_at) < 0 ) {
        perror("clock_gettime created_at");
        reset_wrc_chan(srv, chan_id);
        break;
      }

      strncpy_fixed(chan->wrc_label, WEBRTC_NAME_MAX, WEBRTC_MSG_LABEL(control), ntohs(control->wm_lbllen));
      strncpy_fixed(chan->wrc_proto, WEBRTC_NAME_MAX, WEBRTC_MSG_PROTO(control), ntohs(control->wm_prolen));
      dbg_chan(chan);

      fprintf(stderr, "Opening WebRTC channel\n");

      chan->wrc_family = AF_INET;
      chan->wrc_type = SOCK_DGRAM;

      sk = socket(AF_INET, SOCK_DGRAM, 0);
      if ( sk < 0 ) {
        perror("socket AF_INET control channel");
        release_channel(chan);
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

      chan->wrc_sk = sk;
      arm_channel(chan);

      release_channel(chan);

      ss_prio.assoc_id = g_webrtc_assoc;
      ss_prio.stream_id = WEBRTC_CLIENT_SID(chan_id);
      ss_prio.stream_value = 0xFFFF - control->wm_prio;
      if ( usrsctp_setsockopt(srv, IPPROTO_SCTP, SCTP_SS_VALUE, &ss_prio, sizeof(ss_prio)) < 0 ) {
        perror("usrsctp_setsockopt SCTP_SS_VALUE (client)");
      }

      ss_prio.stream_id = WEBRTC_SERVER_SID(chan_id);
      if ( usrsctp_setsockopt(srv, IPPROTO_SCTP, SCTP_SS_VALUE, &ss_prio, sizeof(ss_prio)) < 0 ) {
        perror("usrsctp_setsockopt SCTP_SS_VALUE (server)");
      }

      // Send ACK message now
      si.snd_sid = WEBRTC_SERVER_SID(chan_id);
      si.snd_flags = 0;
      si.snd_ppid = htonl(WEBRTC_CONTROL_PPID);
      si.snd_context = chan_id;
      si.snd_assoc_id = g_webrtc_assoc;

      ack = WEBRTC_MSG_OPEN_ACK;
      err = usrsctp_sendv(srv, (void *)&ack, sizeof(ack), NULL, 0,
                          (void *) &si, sizeof(si),
                          SCTP_SENDV_SNDINFO, 0);
      if ( err < 0 ) {
        perror("usrsctp_sendv WEBRTC_MSG_OPEN_ACK");
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
    fprintf(stderr, "Unknown PPID %d\n", ntohl(rcv->rcv_ppid));
  }
}

void usage() {
  fprintf(stderr, "webrtc-proxy - WebRTC -> sockets proxy\n");
  fprintf(stderr, "Usage: webrtc-proxy <SCTP UDP port> <capability>\n");
}

int main(int argc, char **argv) {
  uint16_t port;
  int on = 1, i = 0;
  struct socket *sock;
  struct sctp_udpencaps encaps;

  struct sctp_event event;
  uint16_t event_types[] = {
    SCTP_ASSOC_CHANGE,
    SCTP_STREAM_RESET_EVENT,
    SCTP_REMOTE_ERROR,
    SCTP_SHUTDOWN_EVENT,
    SCTP_ADAPTATION_INDICATION,
    SCTP_PARTIAL_DELIVERY_EVENT
  };

  struct sockaddr_in addr;

  char name[INET_ADDRSTRLEN];
  socklen_t infolen, from_len;
  struct sctp_rcvinfo rcv_info;
  unsigned int infotype;
  int flags, n;

  struct sctp_initmsg init;

  char buffer[PROXY_BUF_SIZE];

  sigset_t block;

  if ( argc < 3 ) {
    usage();
    return 1;
  }

  port = atoi(argv[1]);
  g_capability = argv[2];

  memset(g_address_table, 0xFF, sizeof(g_address_table));

  usrsctp_init(port, NULL, debug_printf);
  //  usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);

  sock = usrsctp_socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP,
                        NULL, NULL, 0, NULL);
  if ( !sock ) {
    perror("usrsctp_socket");
    return 1;
  }

  if ( usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_RECVRCVINFO, &on, sizeof(on)) < 0 ) {
    perror("usrsctp_setsockopt SCTP_RECVRCVINFO");
    return 1;
  }

  g_max_strms = sysconf(_SC_OPEN_MAX);

  init.sinit_num_ostreams   = g_max_strms * 2;
  init.sinit_max_instreams  = g_max_strms * 2;
  init.sinit_max_attempts   = 0;
  init.sinit_max_init_timeo = 0;
  if ( usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_INITMSG, &init, sizeof(init)) < 0 ) {
    perror("usrsctp_setsockopt SCTP_INITMSG");
    return 1;
  }

  // Set usrsctp to use remote encapsulation
  memset(&encaps, 0, sizeof(encaps));
  encaps.sue_address.ss_family = AF_INET;
  encaps.sue_port = htons(port);
  if ( usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, (void *)&encaps, sizeof(encaps)) < 0 ) {
    perror("usrsctp_setsockopt SCTP_REMOTE_UDP_ENCAPS_PORT");
    return 1;
  }

  // Register events
  memset(&event, 0, sizeof(event));
  event.se_assoc_id = SCTP_FUTURE_ASSOC;
  event.se_on = 1;
  for ( i = 0; i < sizeof(event_types)/sizeof(event_types[0]); ++i ) {
    event.se_type = event_types[i];
    if ( usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0 ) {
      perror("usrsctp_setsockopt SCTP_EVENT");
    }
  }

  memset(&addr, sizeof(addr), 0);
  addr.sin_family = AF_INET;
  addr.sin_port = htons(5000); // TODO accept this port on command line
  addr.sin_addr.s_addr = INADDR_ANY;
  if ( usrsctp_bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0 ) {
    perror("usrsctp_bind");
    return 1;
  }

  if ( usrsctp_listen(sock, 5) < 0 ) {
    perror("usrsctp_listen");
    return 1;
  }

  while (1) {
    from_len = sizeof(addr);
    flags = 0;
    infolen = sizeof(rcv_info);
    n = usrsctp_recvv(sock, (void *) &buffer, sizeof(buffer),
                      (struct sockaddr *)&addr, &from_len,
                      (void *) &rcv_info, &infolen, &infotype, &flags);

    if ( n > 0 ) {
      if ( flags & MSG_NOTIFICATION ) {
        union sctp_notification *nf = (union sctp_notification *) buffer;
        fprintf(stderr, "Received SCTP notification\n");
        handle_notification(sock, nf, n);
      } else {
        fprintf(stderr, "Message of length %llu received from %s:%u on stream %u with SSN %u and TSN %u, PPID %u, complete %d\n",
                (unsigned long long) n,
                inet_ntop(AF_INET, &addr.sin_addr, name, sizeof(name)), ntohs(addr.sin_port),
                rcv_info.rcv_sid, rcv_info.rcv_ssn, rcv_info.rcv_tsn,
                ntohl(rcv_info.rcv_ppid), (flags & MSG_EOR) ? 1 : 0);

        handle_msg(sock, &rcv_info, infolen, &buffer, n);
      }
    } else {
      perror("usrsctp_recvv");
      return 1;
    }
  }
}
