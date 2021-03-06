#include <signal.h>
#include <openssl/ssl.h>

#include "state.h"
#include "configuration.h"
#include "util.h"
#include "event.h"

void *main_loop(void *state_ptr) {
  struct appstate *state = (struct appstate *) state_ptr;

  eventloop_run(&state->as_eventloop);

  return NULL;
}

int main(int argc, char **argv) {
  struct appconf configuration;
  struct appstate state;

  int nprocs, i, err;

  SSL_library_init();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
  init_static_bio();
  init_appliance_global();

  eventloop_prepare(&state.as_eventloop);
  appconf_init(&configuration);

  if ( appconf_parse_options(&configuration, argc, argv) != 0 )
    return 1;

  if ( appstate_setup(&state, &configuration) < 0 )
    return 2;

  if ( configuration.ac_dump_packet_file )
    bridge_enable_debug(&state.as_bridge, configuration.ac_dump_packet_file);

  //  eventloop_set_debug(&state.as_eventloop, EL_FLAG_DEBUG | EL_FLAG_DEBUG_VERBOSE);

  nprocs = sysconf(_SC_NPROCESSORS_ONLN);
  for ( i = 1; i < nprocs; ++i ) {
    pthread_t new_thread;
    err = pthread_create(&new_thread, NULL, main_loop, (void *) &state);
    if ( err != 0 ) {
      fprintf(stderr, "Could not create thread: %s\n", strerror(err));
      return 1;
    }
  }

  // Try to launch a persona thingy
//  do {
//    sigset_t blkd, old;
//    sigfillset(&blkd);
//    pthread_sigmask(SIG_SETMASK, &blkd, &old);
//    persona_run_ping_test(state.as_personas);
//    pthread_sigmask(SIG_SETMASK, &old, &blkd);
//  } while(0);

  appstate_start_services(&state, &configuration);
  main_loop(&state);

  return 0;
}
