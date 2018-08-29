#ifndef __flock_event_H__
#define __flock_event_H__

#include <pthread.h>
#include <stdint.h>
#include <sys/time.h>
#include <netdb.h>

struct timersub;
struct qdevtsub;

struct eventloop {
  int      el_epoll_fd;
  uint32_t el_flags;

  pthread_mutex_t el_async_mutex;
  pthread_cond_t el_async_cond;
  int el_async_thread_cnt;
  pthread_t *el_async_jobs;
  struct qdevtsub *el_first_async, *el_last_async;

  pthread_mutex_t el_tmr_mutex;
  uint32_t el_tmr_count;
  struct timersub *el_next_tmr;
  struct qdevtsub *el_first_finished, *el_last_finished;
};

#define EL_FLAG_DEBUG             0x00000001
#define EL_FLAG_DEBUG_TIMERS      0x00000002
#define EL_FLAG_DEBUG_VERBOSE     0x00000004
#define EL_FLAG_TMR_INIT          0x80000000
#define EL_FLAG_ASYNC_MUTEX_INIT  0x40000000
#define EL_FLAG_ASYNC_COND_INIT   0x20000000

#define EL_FLAG_DEBUG_MASK    0x0000000F

int eventloop_init(struct eventloop *el);
void eventloop_clear(struct eventloop *el);
void eventloop_release(struct eventloop *el);

void eventloop_set_debug(struct eventloop *el, int debug);

void eventloop_prepare(struct eventloop *el);
void eventloop_run(struct eventloop *el);

/**
 * Invokes the given event in an asynchronous thread. On error, returns -1 and errno is set
 */
int eventloop_invoke_async(struct eventloop *el, struct qdevtsub *evt);
void eventloop_queue(struct eventloop *el, struct qdevtsub *evt);

typedef void (*evtctlfn)(struct eventloop *el, int, void *);

#define EVT_CTL_DESTROY 0x1
#define EVT_CTL_WORK_COMPLETE 0x2
#define EVT_CTL_CUSTOM  0x100

// subscriptions

// files
struct fdsub {
  uint32_t fds_subscriptions;
  evtctlfn fds_fn;
  int      fds_op;
};

#define FD_SUB_READ       0x1
#define FD_SUB_ACCEPT     FD_SUB_READ
#define FD_SUB_WRITE      0x2
#define FD_SUB_HUP        0x4
#define FD_SUB_RDHUP      0x8
#define FD_SUB_READ_OOB   0x10
#define FD_SUB_WRITE_OOB  0x20
#define FD_SUB_ERROR      0x40

#define STATE_FROM_FDSUB(type, field, sub) STRUCT_FROM_BASE(type, field, sub)

void fdsub_init(struct fdsub *sub, struct eventloop *el, int fd, int op, evtctlfn fn);
void fdsub_clear(struct fdsub *sub);

// Returns 0 on success, -1 on error
int set_socket_nonblocking(int fd);

void eventloop_subscribe_fd(struct eventloop *el, int fd, struct fdsub *sub);
void eventloop_unsubscribe_fd(struct eventloop *el, int fd, struct fdsub *sub);

struct qdevtsub {
  struct qdevtsub *qe_next;
  evtctlfn         qe_fn;
  int              qe_op;
};

#define qdevtsub_init(sub, op, fn) \
  if (1) {                         \
    (sub)->qe_next = NULL;         \
    (sub)->qe_fn = fn;             \
    (sub)->qe_op = op;             \
  }
void qdevtsub_deliver(struct eventloop *el, struct qdevtsub *sub);

// DNS resolution
struct dnssub {
  struct qdevtsub ds_queued;
  struct qdevtsub ds_async_resolver;

  const char *ds_node;
  const char *ds_service;

  uint32_t ds_flags;

  int   ds_error;
  struct addrinfo ds_hints;
  struct addrinfo *ds_result;
};

#define DNSSUB_FLAG_FREE_NODE         0x1
#define DNSSUB_FLAG_FREE_SERVICE      0x2
#define DNSSUB_FLAG_USE_DEFAULT_HINTS 0x4
#define DNSSUB_FLAG_ERR_SYSTEM        0x8

void dnssub_init(struct dnssub *dns, int op, evtctlfn fn);
void dnssub_reset(struct dnssub *dns);
#define dnssub_release(dns) dnssub_reset(dns)

int dnssub_start_resolution(struct dnssub *dns, struct eventloop *el,
                            const char *hostname, const char *service,
                            uint32_t dns_flags, struct addrinfo *hints);

#define dnssub_result(d) ((d)->ds_result)
#define dnssub_error(d) ((d)->ds_error)
#define dnssub_strerror(d) ((d)->ds_flags & DNSSUB_FLAG_ERR_SYSTEM ? \
                            strerror((d)->ds_error) : gai_strerror((d)->ds_error))

// timer
struct timersub {
  // Timer mutex must be held in event loop to access these
  union {
    struct qdevtsub ts_queued;
    struct {
      struct timersub *ts_right;
      evtctlfn         ts_fn;
      int              ts_op;
    };
  };
  struct timersub *ts_left, *ts_parent;

  // This can be accessed unless the timer is subscribed (the two fields below are set)
  struct timespec ts_when;
};

// If the ts_left field is null, then ts_right points to the next completed timer
#define ts_next ts_right

#define TIMERSUB_NEXT_COMPLETE(sub) ((sub)->ts_left ? NULL : (sub)->ts_right)

void timersub_init_default(struct timersub *sub, int op, evtctlfn fn);
void timersub_init_at(struct timersub *sub, struct timespec *when, int op, evtctlfn fn);
void timersub_init_from_now(struct timersub *sub, int millis, int op, evtctlfn fn);

void timersub_set(struct timersub *sub, struct timespec *when);
void timersub_set_from_now(struct timersub *sub, int millis);

void eventloop_subscribe_timer(struct eventloop *el, struct timersub *sub);
void eventloop_update_timer(struct eventloop *el, struct timersub *sub);
void eventloop_unsubscribe_timer(struct eventloop *el, struct timersub *sub);

void eventloop_dbg_verify_timers(struct eventloop *el);

// events

struct event {
  int ev_type;
};

#define EV_TYPE_FD      0x1
#define EV_TYPE_QUEUED  0x2

// Files

struct fdevent {
  struct event  fde_ev;

  struct fdsub *fde_sub;
  uint32_t      fde_triggered;
};

#define FD_WRITE_AVAILABLE(ev) ((ev)->fde_triggered & (FD_SUB_WRITE | FD_SUB_WRITE_OOB))
#define FD_READ_PENDING(ev) ((ev)->fde_triggered & (FD_SUB_READ | FD_SUB_READ_OOB))
#define IS_FDEVENT(ev) ((ev)->fde_ev.ev_type == EV_TYPE_FD)

// Timers

struct qdevent {
  struct event qde_ev;
  union {
    struct timersub *qde_timersub;
    struct dnssub   *qde_dnssub;
    struct qdevtsub *qde_sub;
  };
};

#endif
