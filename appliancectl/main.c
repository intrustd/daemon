#include <string.h>
#include <stdio.h>

#include "local_proto.h"
#include "commands.h"

static struct {
  const char *cmd_name;
  int (*cmd_main)(int, char **);
} commands[] = {
  { "create-persona", create_persona },
  { "join-flock", join_flock },
  { NULL, 0 }
};

int create_persona(int argc, char **argv) {
  printf("create persona\n");
  return 0;
}

void usage() {
  int i;
  fprintf(stderr, "appliancectl - Control a running appliance\n");
  fprintf(stderr, "Usage: appliancectl [SUBCOMMAND] [OPTIONS...]\n\n");
  fprintf(stderr, "Subcommands:\n");

  for ( i = 0; commands[i].cmd_name; i++ ) {
    fprintf(stderr, "  %s\n", commands[i].cmd_name);
  }
}

int main(int argc, char **argv) {
  int i;

  if ( argc < 2 ) {
    usage();
    return 1;
  }

  for ( i = 0; commands[i].cmd_name; i++ ) {
    if ( strcmp(argv[1], commands[i].cmd_name) == 0 ) {
      return commands[i].cmd_main(argc - 1, argv + 1);
    }
  }

  fprintf(stderr, "Unrecognized command '%s'\n", argv[1]);
  usage();
  return 2;
}
