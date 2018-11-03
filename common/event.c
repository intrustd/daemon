#include <signal.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <limit.h>

#include "util.h"
#include "event.h"
#include "process.h"

#define OP_DNSSUB_START_RESOLUTION EVT_CTL_CUSTOM

int g_cur_sigchld = 0;

// Timer utilities

int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y)
{
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

void timespec_to_timeval(struct timespec *ts, struct timeval *tv) {
  tv->tv_sec = ts->tv_sec;
  tv->tv_usec = ts->tv_nsec / 1000;
}

static inline int timeval_lt(struct timeval *a, struct timeval *b) {
  return ( a->tv_sec < b->tv_sec ) ||
    ( a->tv_sec == b->tv_sec && a->tv_usec < b->tv_usec );
}

static inline int timespec_lt(struct timespec *a, struct timespec *b) {
  return ( a->tv_sec < b->tv_sec ) ||
    ( a->tv_sec == b->tv_sec && a->tv_nsec < b->tv_nsec );
}

// Linux epoll

static uint32_t translate_from_epoll_flags(int epevs) {
  uint32_t events = 0;

  if ( epevs & EPOLLIN    ) events |= FD_SUB_READ;
  if ( epevs & EPOLLOUT   ) events |= FD_SUB_WRITE;
  if ( epevs & EPOLLHUP   ) events |= FD_SUB_HUP;
  if ( epevs & EPOLLRDHUP ) events |= FD_SUB_RDHUP;
  if ( epevs & EPOLLRDBAND ) events |= FD_SUB_READ_OOB;
  if ( epevs & EPOLLWRBAND ) events |= FD_SUB_WRITE_OOB;
  if ( epevs & EPOLLERR ) events |= FD_SUB_ERROR;

  return events;
}

static int translate_to_epoll_flags(uint32_t evs) {
  int events = EPOLLONESHOT;

  if ( evs & FD_SUB_READ ) events |= EPOLLIN;
  if ( evs & FD_SUB_WRITE ) events |= EPOLLOUT;
  if ( evs & FD_SUB_HUP ) events |= EPOLLHUP;
  if ( evs & FD_SUB_RDHUP ) events |= EPOLLRDHUP;
  if ( evs & FD_SUB_READ_OOB ) events |= EPOLLRDBAND;
  if ( evs & FD_SUB_WRITE_OOB ) events |= EPOLLWRBAND;

  return events;
}

int eventloop_init(struct eventloop *el) {
  int err;
  eventloop_clear(el);

  el->el_epoll_fd = epoll_create1(0);
  if ( el->el_epoll_fd < 0 ) {
    err = errno;
    perror("eventloop_init: epoll_create1");
    el->el_epoll_fd = 0;
    goto error;
  }

  err = pthread_mutex_init(&el->el_tmr_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "eventloop_init: Could not allocate timer mutex\n");
    goto error;
  }
  el->el_flags |= EL_FLAG_TMR_INIT;

  err = pthread_mutex_init(&el->el_async_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "eventloop_init: Could not allocate async mutex\n");
    goto error;
  }
  el->el_flags |= EL_FLAG_ASYNC_MUTEX_INIT;

  err = pthread_cond_init(&el->el_async_cond, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "eventloop_init: Could not allocate async cond\n");
    goto error;
  }
  el->el_flags |= EL_FLAG_ASYNC_COND_INIT;

  err = pthread_mutex_init(&el->el_fd_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "eventloop_init: Could not allocate fd mutex\n");
    goto error;
  }
  el->el_flags |= EL_FLAG_FD_MUTEX_INIT;

  err = pthread_mutex_init(&el->el_ps_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "eventloop_init: Could not allocate process mutex\n");
    goto error;
  }
  el->el_flags |= EL_FLAG_PS_MUTEX_INIT;

  return 0;

 error:
  eventloop_release(el);
  return err;
}

void eventloop_clear(struct eventloop *el) {
  el->el_epoll_fd = 0;
  el->el_flags = 0;
  el->el_async_thread_cnt = 0;
  el->el_async_jobs = NULL;
  el->el_tmr_count = 0;
  el->el_next_tmr = NULL;
  el->el_first_finished = el->el_last_finished = NULL;
  el->el_first_async = el->el_last_async = NULL;
  DLIST_INIT(&el->el_processes);
  el->el_last_sigchld = __sync_fetch_and_or(&g_cur_sigchld, 0);
}

void eventloop_release(struct eventloop *el) {
  if ( el->el_epoll_fd )
    close(el->el_epoll_fd);

  if ( el->el_flags & EL_FLAG_ASYNC_MUTEX_INIT ) {
    int i;
    pthread_mutex_lock(&el->el_async_mutex);

    for ( i = 0; i < el->el_async_thread_cnt; ++i ) {
      pthread_kill(el->el_async_jobs[i], SIGTERM);
      pthread_join(el->el_async_jobs[i], NULL);
    }
    if ( el->el_async_jobs )
      free(el->el_async_jobs);
    el->el_async_thread_cnt = 0;

    if ( el->el_flags & EL_FLAG_ASYNC_COND_INIT )
      pthread_cond_destroy(&el->el_async_cond);

    pthread_mutex_unlock(&el->el_async_mutex);
    pthread_mutex_destroy(&el->el_async_mutex);
  }
  el->el_flags &= ~(EL_FLAG_ASYNC_MUTEX_INIT | EL_FLAG_ASYNC_COND_INIT);

  if ( el->el_flags & EL_FLAG_FD_MUTEX_INIT )
    pthread_mutex_destroy(&el->el_fd_mutex);
  el->el_flags &= ~EL_FLAG_FD_MUTEX_INIT;

  if ( el->el_flags & EL_FLAG_PS_MUTEX_INIT )
    pthread_mutex_destroy(&el->el_ps_mutex);
  el->el_flags &= ~EL_FLAG_PS_MUTEX_INIT;

  if ( el->el_flags & EL_FLAG_TMR_INIT )
    pthread_mutex_destroy(&el->el_tmr_mutex);
  el->el_flags &= ~EL_FLAG_TMR_INIT;

  // TODO free async and finished queues

  eventloop_clear(el);
}

void eventloop_set_debug(struct eventloop *el, int debug) {
  el->el_flags = (el->el_flags & ~EL_FLAG_DEBUG_MASK) |
    (debug & EL_FLAG_DEBUG_MASK);
}

void sigalrm(int sig) {
  //write(STDERR_FILENO, "SIGALRM\n", 8);
}

void sigchld(int sig) {
  int err = write(STDERR_FILENO, "SIGCHLD\n", 8);
  __sync_fetch_and_add(&g_cur_sigchld, 1);
  (void) err;
}

void eventloop_prepare(struct eventloop *el) {
  int err;
  struct sigaction sa;

  sa.sa_handler = sigalrm;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);

  err = sigaction(SIGALRM, &sa, NULL);
  if ( err < 0 )
    perror("sigaction SIGALRM");

  sa.sa_handler = sigchld;
  err = sigaction(SIGCHLD, &sa, NULL);
  if ( err < 0 )
    perror("sigaction SIGCHLD");
}

static struct timersub **eventloop_find_timer_by_idx(struct eventloop *el, uint32_t which) {
  struct timersub **last = NULL;
  uint32_t tmr_mask;

  SAFE_ASSERT(which <= el->el_tmr_count);

  which += 1;

  for ( tmr_mask = 0x80000000; tmr_mask; tmr_mask >>= 1 ) {
    if ( last ) {
      SAFE_ASSERT(*last);
      if ( tmr_mask & which )
        last = &((*last)->ts_right);
      else
        last = &((*last)->ts_left);
    } else if ( tmr_mask & which )
      last = &el->el_next_tmr;
  }

  if ( !last )
    last = &el->el_next_tmr;
  return last;
}

#define FIX_CHILD_PARENTS(t)                                    \
  if (1) {                                                      \
    if ( (t)->ts_left ) (t)->ts_left->ts_parent = (t);          \
    if ( (t)->ts_right ) (t)->ts_right->ts_parent = (t);        \
  }

static void eventloop_timer_sift_up(struct eventloop *el, struct timersub *sub) {
  struct timersub *parent;
  // Now sift up
  while ( sub->ts_parent ) {
    parent = sub->ts_parent;
    if ( timespec_lt(&sub->ts_when, &parent->ts_when) ) {
      // Swap and continue
      if ( parent->ts_left == sub ) {
        struct timersub *parent_right = parent->ts_right;
        sub->ts_parent = parent->ts_parent;

        parent->ts_left = sub->ts_left;
        parent->ts_right = sub->ts_right;

        sub->ts_left = parent;
        sub->ts_right = parent_right;

        FIX_CHILD_PARENTS(parent);
        FIX_CHILD_PARENTS(sub);
      } else if ( parent->ts_right == sub ) {
        struct timersub *parent_left = parent->ts_left;
        sub->ts_parent = parent->ts_parent;

        parent->ts_left = sub->ts_left;
        parent->ts_right = sub->ts_right;

        sub->ts_right = parent;
        sub->ts_left = parent_left;

        FIX_CHILD_PARENTS(parent);
        FIX_CHILD_PARENTS(sub);
      } else abort();

      // Now we have to reset the value pointed to in our grandparent
      if ( sub->ts_parent ) {
        struct timersub *grandparent = sub->ts_parent;
        if ( grandparent->ts_left == parent )
          grandparent->ts_left = sub;
        else if ( grandparent->ts_right == parent )
          grandparent->ts_right = sub;
        else abort();
        FIX_CHILD_PARENTS(grandparent);
      } else
        el->el_next_tmr = sub;
    } else // Done sifting
      break;
  }
}

static void eventloop_add_timer_to_heap(struct eventloop *el, struct timersub *sub) {
  struct timersub *parent;
  if ( el->el_flags & EL_FLAG_DEBUG_TIMERS )
    fprintf(stderr, "Adding timer to heap with %d timers\n", el->el_tmr_count);

  SAFE_ASSERT( el->el_next_tmr != sub &&
               !sub->ts_parent );

  if ( el->el_tmr_count > 0 ) {
    parent = *(eventloop_find_timer_by_idx(el, (el->el_tmr_count - 1) >> 1));
    SAFE_ASSERT(parent);
    if ( (el->el_tmr_count + 1) & 0x1 ) {
      eventloop_dbg_verify_timers(el);
      SAFE_ASSERT(parent->ts_left && !parent->ts_right);
      parent->ts_right = sub;
    } else {
      eventloop_dbg_verify_timers(el);
      SAFE_ASSERT(!parent->ts_left && !parent->ts_right);
      parent->ts_left = sub;
    }
    sub->ts_parent = parent;
  } else {
    el->el_next_tmr = sub;
    sub->ts_parent = NULL;
  }
  el->el_tmr_count++;

  eventloop_timer_sift_up(el, sub);
}

static void eventloop_remove_timer_from_heap(struct eventloop *el, struct timersub *done) {
  struct timersub **bottommost = eventloop_find_timer_by_idx(el, el->el_tmr_count - 1);
  struct timersub *root, *cur;

  // Swap bottom most with us
  cur = root = *bottommost;
  SAFE_ASSERT(root);

  // Now remove last element from heap from the heap
  if ( el->el_tmr_count > 1 ) {
    struct timersub *parent = root->ts_parent;
    SAFE_ASSERT( parent );
    if ( parent->ts_left == root ) {
      SAFE_ASSERT(!parent->ts_right);
      parent->ts_left = NULL;
    } else {
      SAFE_ASSERT(parent->ts_right == root);
      parent->ts_right = NULL;
    }
  }

  root->ts_left = done->ts_left;
  root->ts_right = done->ts_right;
  root->ts_parent = done->ts_parent;
  done->ts_left = NULL;
  done->ts_right = NULL;

  FIX_CHILD_PARENTS(root);

  el->el_tmr_count--;

  if ( cur->ts_parent && timespec_lt(&cur->ts_when, &cur->ts_parent->ts_when) ) {
    if ( done->ts_parent->ts_left == done )
      done->ts_parent->ts_left = cur;
    else if ( done->ts_parent->ts_right == done )
      done->ts_parent->ts_right = cur;
    else
      abort();
    eventloop_timer_sift_up(el, cur);
  } else {
    struct timersub **sift_parent = &root;
    // Now sift down
    while ( 1 ) {
      int dir = 0;

      if ( cur->ts_left && cur->ts_right && timespec_lt(&cur->ts_right->ts_when, &cur->ts_when) ) {
        dir = 1;
      }

      if ( cur->ts_left ) {
        if ( dir == 0 && timespec_lt(&cur->ts_left->ts_when, &cur->ts_when) )
          dir = -1;
        else if ( dir > 0 && timespec_lt(&cur->ts_left->ts_when, &cur->ts_right->ts_when) )
          dir = -1;
      }

      if ( dir == 0 ) break;
      else if ( dir > 0 ) {
        struct timersub *child = cur->ts_right, *cur_left = cur->ts_left;
        // Swap right and cur
        child->ts_parent = cur->ts_parent;

        cur->ts_right = child->ts_right;
        cur->ts_left = child->ts_left;

        child->ts_right = cur;
        child->ts_left = cur_left;

        FIX_CHILD_PARENTS(cur);
        FIX_CHILD_PARENTS(child);

        *sift_parent = child;
        sift_parent = &child->ts_right;
      } else {
        struct timersub *child = cur->ts_left, *cur_right = cur->ts_right;
        // Swap left and cur
        child->ts_parent = cur->ts_parent;

        cur->ts_left = child->ts_left;
        cur->ts_right = child->ts_right;

        child->ts_left = cur;
        child->ts_right = cur_right;

        FIX_CHILD_PARENTS(cur);
        FIX_CHILD_PARENTS(child);

        *sift_parent = child;
        sift_parent = &child->ts_left;
      }
    }

    root = root == done ? NULL : root;
    if ( done->ts_parent ) {
      if ( done->ts_parent->ts_left == done ) {
        done->ts_parent->ts_left = root;
      } else if ( done->ts_parent->ts_right == done ){
        done->ts_parent->ts_right = root;
      } // else assert(0);

      FIX_CHILD_PARENTS(done->ts_parent);
    } else
      el->el_next_tmr = root;
  }
}

int eventloop_cancel_timer(struct eventloop *el, struct timersub *sub) {
  int ret = 0;

  SAFE_MUTEX_LOCK(&el->el_tmr_mutex);

  if ( el->el_flags & (EL_FLAG_DEBUG | EL_FLAG_DEBUG_VERBOSE) ) {
    fprintf(stderr, "eventloop_cancel_timer: %p %p\n", el, sub);
  }

  // Check if the sub is part of the eventloop
  if ( el->el_next_tmr == sub || sub->ts_parent ) {
    // The subscription is part of the heap
    eventloop_remove_timer_from_heap(el, sub);
    if ( el->el_flags & EL_FLAG_DEBUG )
      eventloop_dbg_verify_timers(el);
    ret = 1;
  } else if ( el->el_first_finished == &sub->ts_queued || (!sub->ts_left && sub->ts_right) ) {
    // The child is part of the queue and needs to be removed from it
    struct qdevtsub *left, *cur;

    ret = 1;
    // TODO this may be a very expensive operation.
    // Does it make sense to have a doubly linked list?
    for ( cur = el->el_first_finished, left = NULL;
          cur && cur != &sub->ts_queued;
          left = cur, cur = cur->qe_next );

    if ( cur == &sub->ts_queued ) {
      left->qe_next = sub->ts_queued.qe_next;
    } else {
      fprintf(stderr, "eventloop_cancel_timer: timer not found in completion queue\n");
      abort();
    }
  } else {
    ret = 0;
  }

  sub->ts_parent = sub->ts_left = sub->ts_right = NULL;

  pthread_mutex_unlock(&el->el_tmr_mutex);
  return ret;
}

static inline void eventloop_queue_unlocked(struct eventloop *el, struct qdevtsub *sub) {
  if ( el->el_first_finished ) {
    SAFE_ASSERT(el->el_last_finished);
    el->el_last_finished->qe_next = sub;
    el->el_last_finished = sub;
  } else {
    el->el_first_finished = el->el_last_finished = sub;
  }
}

static void eventloop_mark_timer_completed(struct eventloop *el) {
  struct timersub *done = el->el_next_tmr;
  eventloop_remove_timer_from_heap(el, done);

  /* struct timersub **bottommost = eventloop_find_timer_by_idx(el, el->el_tmr_count - 1); */
  /* struct timersub *done = el->el_next_tmr, *root, *cur, **sift_parent = &root; */

  /* // Swap bottom most with us */
  /* cur = root = *bottommost; */
  /* assert(root); */

  /* // Now remove root from the heap */
  /* if ( el->el_tmr_count > 1 ) { */
  /*   struct timersub *parent = root->ts_parent; */
  /*   assert( parent ); */
  /*   if ( parent->ts_left == root ) { */
  /*     assert(!parent->ts_right); */
  /*     parent->ts_left = NULL; */
  /*   } else { */
  /*     assert(parent->ts_right == root); */
  /*     parent->ts_right = NULL; */
  /*   } */
  /* } */

  /* root->ts_left = done->ts_left; */
  /* root->ts_right = done->ts_right; */
  /* root->ts_parent = NULL; */
  /* done->ts_left = NULL; */
  /* done->ts_right = NULL; */
  /* done->ts_parent = NULL; */

  /* // Now sift down */
  /* while ( 1 ) { */
  /*   int dir = 0; */

  /*   if ( cur->ts_left && cur->ts_right && timespec_lt(&cur->ts_right->ts_when, &cur->ts_when) ) { */
  /*     dir = 1; */
  /*   } */

  /*   if ( cur->ts_left ) { */
  /*     if ( dir == 0 && timespec_lt(&cur->ts_left->ts_when, &cur->ts_when) ) */
  /*       dir = -1; */
  /*     else if ( dir > 0 && timespec_lt(&cur->ts_left->ts_when, &cur->ts_right->ts_when) ) */
  /*       dir = -1; */
  /*   } */

  /*   if ( dir == 0 ) break; */
  /*   else if ( dir > 0 ) { */
  /*     struct timersub *child = cur->ts_right, *cur_left = cur->ts_left; */
  /*     // Swap right and cur */
  /*     child->ts_parent = cur->ts_parent; */

  /*     cur->ts_right = child->ts_right; */
  /*     cur->ts_left = child->ts_left; */

  /*     child->ts_right = cur; */
  /*     child->ts_left = cur_left; */

  /*     FIX_CHILD_PARENTS(cur); */
  /*     FIX_CHILD_PARENTS(child); */

  /*     *sift_parent = child; */
  /*     sift_parent = &child->ts_right; */
  /*   } else { */
  /*     struct timersub *child = cur->ts_left, *cur_right = cur->ts_right; */
  /*     // Swap left and cur */
  /*     child->ts_parent = cur->ts_parent; */

  /*     cur->ts_left = child->ts_left; */
  /*     cur->ts_right = child->ts_right; */

  /*     child->ts_left = cur; */
  /*     child->ts_right = cur_right; */

  /*     FIX_CHILD_PARENTS(cur); */
  /*     FIX_CHILD_PARENTS(child); */

  /*     *sift_parent = child; */
  /*     sift_parent = &child->ts_left; */
  /*   } */
  /* } */

  /* el->el_tmr_count--; */
  /* el->el_next_tmr = root == done ? NULL : root; */

  // Now add the completed timer
  done->ts_left = done->ts_right = done->ts_parent = NULL;
  eventloop_queue_unlocked(el, &done->ts_queued);
}

static int eventloop_deliver_timers(struct eventloop *el) {
  int delivered = 0;
  struct timespec now;
  struct timeval now_tv, when_tv;

  if ( clock_gettime(CLOCK_REALTIME, &now) < 0 )
    perror("clock_gettime");

  timespec_to_timeval(&now, &now_tv);

  while ( el->el_next_tmr ) {
    timespec_to_timeval(&el->el_next_tmr->ts_when, &when_tv);

    if ( timeval_lt(&when_tv, &now_tv) ) {
      delivered++;
      SAFE_ASSERT(el->el_tmr_count > 0);
      if ( el->el_flags & EL_FLAG_DEBUG_TIMERS )
        eventloop_dbg_verify_timers(el);

      if ( el->el_flags & (EL_FLAG_DEBUG | EL_FLAG_DEBUG_VERBOSE) ) {
        fprintf(stderr, "eventloop_deliver_timers: %p %p\n", el, el->el_next_tmr);
      }

      eventloop_mark_timer_completed(el);
    } else
      break;
  }

  return delivered;
}

static int eventloop_deliver_processes(struct eventloop *el) {
  int delivered = 0;
  struct pssub *cur, *tmp;

  DLIST_ITER(&el->el_processes, ps_list, cur, tmp) {
    int sts;
    pid_t exited = waitpid(cur->ps_which, &sts, WNOHANG);
    if ( exited < 0 )
      perror("eventloop_deliver_processes: waitpid");
    else if ( exited == cur->ps_which ) {
      cur->ps_status = sts;
      eventloop_queue(el, &cur->ps_on_complete);
      DLIST_REMOVE(&el->el_processes, ps_list, cur);
      delivered++;
    } else if ( exited == 0 ) continue;
    else {
      fprintf(stderr, "eventloop_deliver_processes: waitpid malfunction: returned a different PID than the one waited for\n");
      abort();
    }
  }

  return delivered;
}

static void eventloop_reset_timer(struct eventloop *el) {
  struct itimerval it;
  struct timespec now;
  struct timeval when_tv, now_tv;
  int err;

  if ( !el->el_next_tmr ) {
    if ( el->el_flags & EL_FLAG_DEBUG_TIMERS )
      fprintf(stderr, "Not setting itimer because there are no timers\n");
    return;
  }

  it.it_interval.tv_sec = 0;
  it.it_interval.tv_usec = 0;

  err = clock_gettime(CLOCK_REALTIME, &now);
  if ( err < 0 )
    perror("clock_gettime");

  timespec_to_timeval(&now, &now_tv);
  timespec_to_timeval(&el->el_next_tmr->ts_when, &when_tv);

  if ( timeval_subtract(&it.it_value, &when_tv, &now_tv) ) {
    it.it_value.tv_sec = 0;
    it.it_value.tv_usec = 1;
  }

  if ( el->el_flags & EL_FLAG_DEBUG_TIMERS )
    fprintf(stderr, "Set itimer %ld %ld\n", it.it_value.tv_sec, it.it_value.tv_usec);

  err = setitimer(ITIMER_REAL, &it, NULL);
  if ( err < 0 )
    perror("setitimer");
}

static int eventloop_pop_queued(struct eventloop *el, struct qdevent *evt) {
  int ret;

  if ( pthread_mutex_lock(&el->el_tmr_mutex) != 0 ) return 0;

  if ( el->el_first_finished ) {
    SAFE_ASSERT(el->el_last_finished);

    evt->qde_ev.ev_type = EV_TYPE_QUEUED;
    evt->qde_sub = el->el_first_finished;

    el->el_first_finished = el->el_first_finished->qe_next;
    if ( !el->el_first_finished )
      el->el_last_finished = NULL;
    else {
      // Because there are more timers ready, we send a signal to
      // ourselves which will wake other threads
      if ( kill(getpid(), SIGALRM) < 0 )
        perror("raise");
    }

    evt->qde_sub->qe_next = NULL;
    ret = 1;
  } else
    ret = 0;

  pthread_mutex_unlock(&el->el_tmr_mutex);

  return ret;
}

void eventloop_run(struct eventloop *el) {
  int err;
  struct epoll_event ev;
  sigset_t blocked_signals, old_signals;

  sigfillset(&blocked_signals);
  sigdelset(&blocked_signals, SIGINT); // TODO
  // Block all signals
  err = pthread_sigmask(SIG_SETMASK, &blocked_signals, &old_signals);
  if ( err != 0 ) {
    fprintf(stderr, "pthread_sigmask: %s\n", strerror(err));
    return;
  }

  sigdelset(&old_signals, SIGALRM);
  sigdelset(&old_signals, SIGCHLD);

  while (1) {
    struct qdevent evt;
    if ( eventloop_pop_queued(el, &evt) ) {
      evt.qde_timersub->ts_fn(el, evt.qde_timersub->ts_op, &evt);
    } else {

      err = epoll_pwait(el->el_epoll_fd, &ev, 1, -1, &old_signals);
      if ( err < 0 ) {
        if ( errno == EINTR ) {
          int cur_sigchld;
          //          fprintf(stderr, "pwait interrupted\n");

          pthread_mutex_lock(&el->el_tmr_mutex);
          eventloop_deliver_timers(el);
          eventloop_reset_timer(el);
          pthread_mutex_unlock(&el->el_tmr_mutex);

          //fprintf(stderr, "Done delivering timers\n");

          pthread_mutex_lock(&el->el_ps_mutex);
          cur_sigchld = __sync_fetch_and_or(&g_cur_sigchld, 0);
          if ( cur_sigchld != el->el_last_sigchld ) {
            el->el_last_sigchld = cur_sigchld;
            eventloop_deliver_processes(el);
          }
          pthread_mutex_unlock(&el->el_ps_mutex);

          continue;
        } else {
          perror("eventloop_run: epoll_wait");
          return;
        }
      } else if ( err == 0 ) {
        fprintf(stderr, "Timeout\n");
      } else {
        struct fdsub *sub;
        struct fdevent fd_event;

        // Dispatch

        sub = (struct fdsub *) ev.data.ptr;
        fd_event.fde_ev.ev_type = EV_TYPE_FD;
        fd_event.fde_sub = sub;
        fd_event.fde_triggered = translate_from_epoll_flags(ev.events);

        if ( el->el_flags & EL_FLAG_DEBUG )
          fprintf(stderr, "Dispatching event %04x\n", fd_event.fde_triggered);

        SAFE_MUTEX_LOCK(&el->el_fd_mutex);
        if ( el->el_flags & EL_FLAG_DEBUG ) {
          fprintf(stderr, "Before check %04x\n", sub->fds_subd);
        }
        fd_event.fde_triggered &= sub->fds_subd;  // Only deliver events currently subscribed
        sub->fds_subd &= ~fd_event.fde_triggered; // Remove events that are now being delivered
        // TODO do we want to re-enable events
        if ( el->el_flags & EL_FLAG_DEBUG ) {
          fprintf(stderr, "Dispatching event %04x %04x\n", fd_event.fde_triggered, sub->fds_subd);
        }
        pthread_mutex_unlock(&el->el_fd_mutex);

        if ( fd_event.fde_triggered )
          sub->fds_fn(el, sub->fds_op, (void *) &fd_event);
        else {
          //fprintf(stderr, "Skipping event because it was unsubscribed while being delivered\n");
        }
      }
    }
  }
}

static void *eventloop_async_thread(void *arg) {
  struct eventloop *el = (struct eventloop *) arg;
  int err;
  sigset_t working_signals, checking_signals;

  sigfillset(&working_signals);
  err = pthread_sigmask(SIG_SETMASK, &working_signals, NULL);
  if ( err != 0 )
    fprintf(stderr, "eventloop_async_thread: pthread_sigmask(&working_signals): %s\n", strerror(err));

  sigfillset(&checking_signals); // Signals that are enabled while checking
  sigdelset(&checking_signals, SIGTERM);

  while (1) {
    struct qdevtsub *work_item;
    struct qdevent evt;

    // Attempt to find a valid work item
    pthread_mutex_lock(&el->el_async_mutex);
    err = pthread_sigmask(SIG_SETMASK, &checking_signals, NULL);
    if ( err != 0 )
      fprintf(stderr, "eventloop_async_thread: pthread_sigmask(&checking_signals): %s\n", strerror(err));

    while ( !el->el_first_async )
      pthread_cond_wait(&el->el_async_cond, &el->el_async_mutex);

    err = pthread_sigmask(SIG_SETMASK, &working_signals, NULL);
    if ( err != 0 )
      fprintf(stderr, "eventloop_async_thread: pthread_sigmask(&working_signals): %s\n", strerror(err));

    work_item = el->el_first_async;
    el->el_first_async = work_item->qe_next;
    if ( !el->el_first_async )
      el->el_last_async = NULL;

    pthread_mutex_unlock(&el->el_async_mutex);

    evt.qde_ev.ev_type = EV_TYPE_QUEUED;
    evt.qde_sub = work_item;
    work_item->qe_fn(el, work_item->qe_op, &evt);
  }

  return NULL;
}

int eventloop_queue(struct eventloop *el, struct qdevtsub *sub) {
  int ret = 0;
  if ( pthread_mutex_lock(&el->el_tmr_mutex) != 0 ) {
    fprintf(stderr, "eventloop_queue: could not lock mutex\n");
    ret = 0;
  } else {
    if ( el->el_last_finished == sub || sub->qe_next )
      ret = 0;
    else {
      eventloop_queue_unlocked(el, sub);
      kill(getpid(), SIGALRM);
      ret = 1;
    }
    pthread_mutex_unlock(&el->el_tmr_mutex);
  }
  return ret;
}

int eventloop_invoke_async(struct eventloop *el, struct qdevtsub *evt) {
  if ( pthread_mutex_lock(&el->el_async_mutex) != 0 ) {
    errno = EBUSY;
    return -1;
  }

  evt->qe_next = NULL;

  if ( el->el_first_async ) {
    SAFE_ASSERT(el->el_last_async);
    el->el_last_async->qe_next = evt;
    el->el_last_async = evt;
  } else {
    SAFE_ASSERT(!el->el_last_async);
    el->el_last_async = el->el_first_async = evt;
  }

  // Now check to see if we have any threads running
  if ( el->el_async_thread_cnt == 0 ) {
    int nthreads = sysconf(_SC_NPROCESSORS_ONLN), i;

    nthreads /= 2; // Use half of available cores
    if ( nthreads > 4 ) nthreads = 4; // Use at most four cores
    if ( nthreads == 0 ) nthreads = 1; // Use at least one core

    SAFE_ASSERT(nthreads > 0 );

    el->el_async_jobs = malloc(sizeof(*el->el_async_jobs) * nthreads);
    if ( !el->el_async_jobs ) {
      pthread_mutex_unlock(&el->el_async_mutex);

      errno = ENOMEM;
      return -1;
    }

    for ( i = 0; i < nthreads; ++i ) {
      int err = pthread_create(&el->el_async_jobs[i], NULL, eventloop_async_thread, el);
      if ( err != 0 ) {
        fprintf(stderr, "eventloop_invoke_async: pthread_create: %s\n", strerror(err));
        if ( i > 0 )
          el->el_async_jobs = realloc(el->el_async_jobs, sizeof(*el->el_async_jobs) * i);
        goto done;
      }
    }

  done:
    el->el_async_thread_cnt = i;
  }

  pthread_cond_signal(&el->el_async_cond);

  pthread_mutex_unlock(&el->el_async_mutex);

  return 0;
}

// FD events

void fdsub_init(struct fdsub *sub, struct eventloop *el, int fd, int op, evtctlfn fn) {
  struct epoll_event ev;
  int err;

  sub->fds_subd = 0;
  sub->fds_fn = fn;
  sub->fds_op = op;

  ev.events = EPOLLONESHOT;
  ev.data.ptr = (void *) sub;

  err = epoll_ctl(el->el_epoll_fd, EPOLL_CTL_ADD, fd, &ev);
  if ( err < 0 )
    perror("fdsub_init: epoll_ctl");
}

void fdsub_clear(struct fdsub *sub) {
  sub->fds_subd = 0;
  sub->fds_fn = 0;
  sub->fds_op = 0;
}

int set_socket_nonblocking(int sk) {
  int flags = fcntl(sk, F_GETFL);
  if ( flags == -1 ) {
    perror("set_socket_nonblocking: F_GETFL");
    return -1;
  }

  flags = fcntl(sk, F_SETFL, flags | O_NONBLOCK);
  if ( flags == -1 ) {
    perror("set_socket_nonblocking: F_SETFL");
    return -1;
  }

  return 0;
}

int eventloop_subscribe_fd(struct eventloop *el, int fd, uint16_t evs, struct fdsub *sub) {
  int err;
  struct epoll_event ev;
  uint16_t old_subs;

  SAFE_MUTEX_LOCK(&el->el_fd_mutex);

  // Now, add the events into the subscription word. At this point,
  // the added events will be delivered at most once, and they will
  // always be waited for.
  old_subs = sub->fds_subd;
  sub->fds_subd |= evs;

  ev.events = translate_to_epoll_flags(sub->fds_subd | evs);
  ev.data.ptr = (void *) sub;

  err = epoll_ctl(el->el_epoll_fd, EPOLL_CTL_MOD, fd, &ev);
  if ( err < 0 )
    perror("eventloop_subscribe_fd: epoll_ctl");

  pthread_mutex_unlock(&el->el_fd_mutex);

  return evs & ~old_subs;
}

int eventloop_unsubscribe_fd(struct eventloop *el, int fd, uint16_t evs, struct fdsub *sub) {
  int err;
  struct epoll_event ev;
  int old_subs;

  SAFE_MUTEX_LOCK(&el->el_fd_mutex);
  old_subs = sub->fds_subd;
  sub->fds_subd &= ~evs;

  if ( sub->fds_subd == 0 ) {
    err = epoll_ctl(el->el_epoll_fd, EPOLL_CTL_DEL, fd, &ev);
    if ( err < 0 )
      perror("eventloop_unsubscribe_fd: epoll_ctl");
  } else {
    ev.events = translate_to_epoll_flags(sub->fds_subd);
    ev.data.ptr = (void *) sub;

    err = epoll_ctl(el->el_epoll_fd,
                    old_subs == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD,
                    fd, &ev);
    if ( err < 0 )
      perror("eventloop_unsubscribe_fd: epoll_ctl resubscribe");
  }

  pthread_mutex_unlock(&el->el_fd_mutex);

  return evs & old_subs;
}

// Timers
void timersub_init_default(struct timersub *sub, int op, evtctlfn fn) {
  sub->ts_fn = fn;
  sub->ts_op = op;
  sub->ts_parent = sub->ts_left = sub->ts_right = NULL;
}

void timersub_init_at(struct timersub *sub, struct timespec *when, int op, evtctlfn fn) {
  timersub_init_default(sub, op, fn);
  timersub_set(sub, when);
}

void timersub_set(struct timersub *sub, struct timespec *when) {
  memcpy(&sub->ts_when, when, sizeof(sub->ts_when));
}

void timersub_init_from_now(struct timersub *sub, int millis, int op, evtctlfn fn) {
  timersub_init_default(sub, op, fn);
  timersub_set_from_now(sub, millis);
}

void timersub_set_from_now(struct timersub *sub, int millis) {
  int err;
  struct timespec now;

  err = clock_gettime(CLOCK_REALTIME, &now);
  if ( err < 0 )
    perror("clock_gettime");

  now.tv_sec += millis / 1000;
  now.tv_nsec += (millis % 1000) * 1000000;
  now.tv_sec += now.tv_nsec / 1000000000;
  now.tv_nsec %= 1000000000;

  timersub_set(sub, &now);
}

void eventloop_subscribe_timer(struct eventloop *el, struct timersub *sub) {
  pthread_mutex_lock(&el->el_tmr_mutex);
  if ( el->el_flags & (EL_FLAG_DEBUG | EL_FLAG_DEBUG_VERBOSE) ) {
    fprintf(stderr, "eventloop_subscribe_timer: %p %p\n", el, sub);
  }
  sub->ts_left = sub->ts_right = NULL;
  eventloop_add_timer_to_heap(el, sub);
  if ( el->el_next_tmr == sub ) // Reset itimer
    eventloop_reset_timer(el);
  pthread_mutex_unlock(&el->el_tmr_mutex);
}

void eventloop_dbg_verify_timers_(struct timersub *t, uint32_t max, uint32_t ix) {
  if ( ix == max ) SAFE_ASSERT(!t->ts_left && !t->ts_right);
  else {
    if ( t->ts_right ) {
      SAFE_ASSERT(t->ts_left);
      SAFE_ASSERT((ix << 1) <= max);
      SAFE_ASSERT(((ix << 1) | 1) <= max);
      if ( !timespec_lt(&t->ts_when, &t->ts_left->ts_when) ) {
        fprintf(stderr, "timespec_lt(&t->ts_when, &t->ts_left->ts_when) failed at %d\n", ix);
        abort();
      }
      SAFE_ASSERT(timespec_lt(&t->ts_when, &t->ts_right->ts_when));
      eventloop_dbg_verify_timers_(t->ts_left, max, ix << 1);
      eventloop_dbg_verify_timers_(t->ts_right, max, (ix << 1) | 1);
    } else if ( (ix << 1) <= max ) {
      if ( !t->ts_left ) {
        fprintf(stderr, "t->ts_left failed at index %d\n", ix);
        abort();
      }
      SAFE_ASSERT(timespec_lt(&t->ts_when, &t->ts_left->ts_when));
      eventloop_dbg_verify_timers_(t->ts_left, max, ix << 1);
    }
  }
}

void eventloop_dbg_print_heap_(struct timersub *timer, FILE *f, int depth) {
  if ( depth >= 32 ) return;
  if ( !timer ) return;

  fprintf(f, "n%08lx[label=<<B>%08lx</B><BR/>%d<BR/>(%ld.%012ld)>];\n",
          (uintptr_t) timer, (uintptr_t) timer, timer->ts_op,
          timer->ts_when.tv_sec, timer->ts_when.tv_nsec);
  if ( timer->ts_left ) {
    eventloop_dbg_print_heap_(timer->ts_left, f, depth + 1);
    fprintf(f, "n%08lx -> n%08lx [ label=\"L\" ];\n", (uintptr_t) timer, (uintptr_t) timer->ts_left);
  }
  if ( timer->ts_right ) {
    eventloop_dbg_print_heap_(timer->ts_right, f, depth + 1);
    fprintf(f, "n%08lx -> n%08lx [ label=\"R\" ];\n", (uintptr_t) timer, (uintptr_t) timer->ts_right);
  }
  if ( timer->ts_parent )
    fprintf(f, "n%08lx -> n%08lx [ label = \"P\" ];\n", (uintptr_t) timer, (uintptr_t) timer->ts_parent);
}

void eventloop_dbg_print_heap(struct timersub *timer, int iter) {
  char path[PATH_MAX];
  FILE *f;
  snprintf(path, sizeof(path), "graphs/heap%08d.dot", iter);

  f = fopen(path, "wt");
  fprintf(f, "digraph timers {\n");
  eventloop_dbg_print_heap_(timer, f, 1);
  fprintf(f, "}\n");
  fclose(f);
}

void eventloop_dbg_verify_timers(struct eventloop *el) {
  static int iter = 0;

  if ( el->el_flags & EL_FLAG_DEBUG_VERBOSE ) {
    fprintf(stderr, "Printing heap %d\n", iter);
    eventloop_dbg_print_heap(el->el_next_tmr, iter++);
  }

  if ( el->el_next_tmr )
    eventloop_dbg_verify_timers_(el->el_next_tmr, el->el_tmr_count, 1);
}

// DNS resolution

static void dnssubfn(struct eventloop *el, int op, void *arg) {
  struct dnssub *dns;
  struct qdevent *evt;
  int err;

  switch ( op ) {
  case OP_DNSSUB_START_RESOLUTION:
    evt = (struct qdevent *) arg;
    dns = STRUCT_FROM_BASE(struct dnssub, ds_async_resolver, evt->qde_sub);

    err = getaddrinfo(dns->ds_node, dns->ds_service,
                      ((dns->ds_flags & DNSSUB_FLAG_USE_DEFAULT_HINTS) ?
                       NULL : &dns->ds_hints),
                      &dns->ds_result);
    if ( err != 0 ) {
      fprintf(stderr, "getaddrinfo(%s, %s) fails: %s\n", dns->ds_node, dns->ds_service,
              gai_strerror(err));
      dns->ds_flags &= ~DNSSUB_FLAG_ERR_SYSTEM;
      dns->ds_error = err;
    } else
      dns->ds_error = 0;

    eventloop_queue(el, &dns->ds_queued);

    break;
  default:
    fprintf(stderr, "dnssubfn: Unknown op %d\n", op);
  }
}

void dnssub_init(struct dnssub *dns, int op, evtctlfn fn) {
  qdevtsub_init(&dns->ds_queued, op, fn);
  qdevtsub_init(&dns->ds_async_resolver, OP_DNSSUB_START_RESOLUTION, dnssubfn);

  dns->ds_node = dns->ds_service = NULL;
  dns->ds_flags = DNSSUB_FLAG_USE_DEFAULT_HINTS;
  dns->ds_error = 0;
  dns->ds_result = NULL;
}

void dnssub_reset(struct dnssub *dns) {
  if ( dns->ds_result ) {
    freeaddrinfo(dns->ds_result);
    dns->ds_result = NULL;
  }

  if ( dns->ds_node ) {
    if ( dns->ds_flags & DNSSUB_FLAG_FREE_NODE )
      free((void *)dns->ds_node);
    dns->ds_node = NULL;
  }

  if ( dns->ds_service ) {
    if ( dns->ds_flags & DNSSUB_FLAG_FREE_SERVICE )
      free((void *)dns->ds_service);
    dns->ds_service = NULL;
  }

  dns->ds_flags = DNSSUB_FLAG_USE_DEFAULT_HINTS;
  dns->ds_error = 0;
}

int dnssub_start_resolution(struct dnssub *dns, struct eventloop *el,
                            const char *hostname, const char *service,
                            uint32_t dns_flags, struct addrinfo *hints) {

  dnssub_reset(dns);

  if ( hints ) {
    dns->ds_flags &= ~DNSSUB_FLAG_USE_DEFAULT_HINTS;
    memcpy(&dns->ds_hints, hints, sizeof(dns->ds_hints));
  }

  dns->ds_flags |= (dns_flags & (DNSSUB_FLAG_FREE_NODE | DNSSUB_FLAG_FREE_SERVICE));
  dns->ds_node = hostname;
  dns->ds_service = service;

  return eventloop_invoke_async(el, &dns->ds_async_resolver);
}

void eventloop_queue_all(struct eventloop *el, evtqueue *q) {
  if ( pthread_mutex_lock(&el->el_tmr_mutex) != 0 ) {
    fprintf(stderr, "eventloop_queue_all: could not lock mutex\n");
  } else {
    struct qdevtsub *cur, *next;
    for ( cur = *q, next = cur ? cur->qe_next : NULL;
          cur;
          cur = next, next = cur ? cur->qe_next : NULL ) {
      cur->qe_next = NULL;
      eventloop_queue_unlocked(el, cur);
    }
    *q = NULL;
    pthread_mutex_unlock(&el->el_tmr_mutex);
  }
}

void evtqueue_queue(evtqueue *queue, struct qdevtsub *evt) {
  SAFE_ASSERT( !__sync_fetch_and_or(&evt->qe_next, 0) );
  evt->qe_next = *queue;
  *queue = evt;
}
