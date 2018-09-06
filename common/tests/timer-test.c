#include <assert.h>
#include <stdio.h>
#include "../event.h"

#define TIMER_COUNT 500
#define PAR_COUNT 8

struct timersub g_tmrs[TIMER_COUNT];

void timerfn(struct eventloop *el, int op, void *arg) {
  int ix = op - EVT_CTL_CUSTOM;
  int did_cancel = 0;

  fprintf(stderr, "Timer went off: %d\n", op - EVT_CTL_CUSTOM);

  did_cancel = eventloop_cancel_timer(el, &g_tmrs[(op - EVT_CTL_CUSTOM) / PAR_COUNT]);
  if ( ix % PAR_COUNT == 0 )
    assert(did_cancel);
  else
    assert(did_cancel == 0);
}

void timerclfn(struct eventloop *el, int op, void *arg) {
  fprintf(stderr, "Canceled timer went off %d\n", op - EVT_CTL_CUSTOM);
  assert(0);
}

int main(int argc, char **argv) {
  struct timersub tmrs[TIMER_COUNT * PAR_COUNT];
  int i, j, millis = 500;

  struct eventloop el;

  eventloop_init(&el);
  eventloop_prepare(&el);

  for ( i = 0; i < TIMER_COUNT; ++i ) {
    timersub_init_from_now(&g_tmrs[i], millis + i * 100 + i + 50, EVT_CTL_CUSTOM + i, timerclfn);
    eventloop_subscribe_timer(&el, &g_tmrs[i]);
    for ( j = 0; j < PAR_COUNT; ++ j ) {
      timersub_init_from_now(&tmrs[i * PAR_COUNT + j], millis + i * 100, EVT_CTL_CUSTOM + i * PAR_COUNT + j, timerfn);
      eventloop_subscribe_timer(&el, &tmrs[i * PAR_COUNT + j]);
    }
  }

  eventloop_set_debug(&el, EL_FLAG_DEBUG); // | EL_FLAG_DEBUG_TIMERS | EL_FLAG_DEBUG_VERBOSE);
  eventloop_dbg_verify_timers(&el);

  eventloop_run(&el);
}
