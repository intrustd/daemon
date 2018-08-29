#include <openssl/ssl.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include "configuration.h"
#include "state.h"
#include "util.h"

void *main_loop(void *state_ptr) {
  struct flockstate *state = (struct flockstate *) state_ptr;

  eventloop_run(&state->fs_eventloop);

  return NULL;
}

int main(int argc, char **argv) {
  struct flockconf configuration;
  struct flockstate state;
  int nprocs, i;

  SSL_library_init();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
  init_static_bio();

  flockconf_init(&configuration);

  if ( flockconf_parse_options(&configuration, argc, argv) != 0 )
    return 1;

  if ( flockstate_init(&state, &configuration) != 0 )
    return 1;

  //  eventloop_set_debug(&state.fs_eventloop, 1);
  eventloop_prepare(&state.fs_eventloop);

  nprocs = sysconf(_SC_NPROCESSORS_ONLN);
  for ( i = 1; i < nprocs; ++i ) {
    pthread_t new_thread;
    int err = pthread_create(&new_thread, NULL, main_loop, (void *) &state);
    if ( err != 0 ) {
      fprintf(stderr, "Could not create thread: %s\n", strerror(err));
      return 1;
    }
  }

  flockstate_start_services(&state);

  // Start the main loop here
  main_loop(&state);

  return 0;
}
