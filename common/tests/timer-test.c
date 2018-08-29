#include <stdio.h>
#include "../event.h"

#define TIMER_COUNT 1024

void timerfn(struct eventloop *el, int op, void *arg) {
  fprintf(stderr, "Timer went off: %d\n", op - EVT_CTL_CUSTOM);
}

int main(int argc, char **argv) {
  struct timersub tmrs[TIMER_COUNT * 8];
  int i, j, millis = 500;

  struct eventloop el;

  eventloop_init(&el);
  eventloop_prepare(&el);

  for ( i = 0; i < TIMER_COUNT; ++i ) {
    for ( j = 0; j < 8; ++ j ) {
      timersub_init_from_now(&tmrs[i * 8 + j], millis + i * 100, EVT_CTL_CUSTOM + i * 8 + j, timerfn);
      eventloop_subscribe_timer(&el, &tmrs[i * 8 + j]);
    }
  }

  eventloop_set_debug(&el, 1);
  eventloop_dbg_verify_timers(&el);

  eventloop_run(&el);
}
