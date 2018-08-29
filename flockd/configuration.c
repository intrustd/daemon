#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "configuration.h"

static void usage(const char *msg) {
  if ( msg ) fprintf(stderr, "Error: %s\n", msg);

  fprintf(stderr, "flockd - Flock server for stork/kite appliances\n");
  fprintf(stderr, "Usage: flockd [OPTION]...\n\n");
  fprintf(stderr, "Options:\n");
  fprintf(stderr,
          "  -h, --help                Show this help message\n");
  fprintf(stderr,
          "  -c, --cert <certificate>  Set the SSL certificate to use\n");
  fprintf(stderr,
          "  -k, --key <private key>   The private key to use\n");
  fprintf(stderr,
          "  -w, --web <port>          Set the TCP port for websocket\n"
          "                            connections (Default 6854)\n");
  fprintf(stderr,
          "  -p, --port <port>         Set the UDP port for service\n"
          "                            connections (Default 6854)\n");
}

void flockconf_init(struct flockconf *c) {
  c->fc_certificate_file = NULL;
  c->fc_privkey_file = NULL;
  c->fc_shards_file = NULL;
  c->fc_service_port = 0;
  c->fc_websocket_port = 0;
}

int flockconf_parse_options(struct flockconf *c, int argc, char **argv) {
  int help_flag = 0, option_index = 0, err;
  struct option long_options[] = {
    {"help", no_argument, &help_flag, 1},
    {"port", required_argument, 0, 'p'},
    {"web", required_argument, 0, 'w'},
    {"shards", required_argument, 0, 's'},
    {"cert", required_argument, 0, 'c'},
    {"key", required_argument, 0, 'k'},
    {0, 0, 0, 0}
  };

  while (1) {
    err = getopt_long(argc, argv, "hp:w:s:c:k:", long_options, &option_index);
    if ( err == -1 ) break;

    switch (err) {
    default: case 0: break;
    case 'h':
      help_flag = 1;
      break;

    case 'p':
      c->fc_service_port = atoi(optarg);
      break;
    case 'w':
      c->fc_websocket_port = atoi(optarg);
      break;
    case 's':
      c->fc_shards_file = optarg;
      break;
    case 'c':
      c->fc_certificate_file = optarg;
      break;
    case 'k':
      c->fc_privkey_file = optarg;
      break;
    }
  }

  if ( help_flag ) {
    usage(NULL);
    return -1;
  } else {
    return flockconf_validate(c, 1);
  }
}

int flockconf_validate(struct flockconf* c, int do_debug) {
  if ( !c->fc_certificate_file ) {
    usage("No certificate file provided");
    return -1;
  }
  if ( !c->fc_privkey_file ) {
    usage("No private key provided");
    return -1;
  }

  if ( c->fc_service_port == 0 )
    c->fc_service_port = 6854;
  if ( c->fc_websocket_port == 0 )
    c->fc_websocket_port = 6853;

  if ( do_debug )
    fprintf(stderr, "Running service on port %d\nRunning websockets on port %d\n",
            c->fc_service_port, c->fc_websocket_port);

  return 0;
}
