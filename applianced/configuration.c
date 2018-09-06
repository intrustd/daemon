#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "util.h"
#include "configuration.h"

#define VALGRIND_FLAG 0x201

static void usage(const char *msg) {
  if ( msg ) fprintf(stderr, "Error: %s\n", msg);

  fprintf(stderr, "applianced - Kite appliance server\n");
  fprintf(stderr, "Usage: applianced [OPTION]...\n\n");
  fprintf(stderr, "Options:\n");
  fprintf(stderr,
          "  -h, --help                    Show this help message\n");
  fprintf(stderr,
          "  -c, --conf-dir <DIR>          Appliance configuration directory\n");
  fprintf(stderr,
          "  --iproute <IPROUTE>           Path to 'iproute' executable\n");
  fprintf(stderr,
          "  --valgrind                    Make things valgrind compatible\n");
}

static const char *nix_build(const char *pkg_name, const char *suffix) {
  int p[2];
  int err;
  pid_t pid;

  fprintf(stderr, "Building nix package %s\n", pkg_name);

  err = pipe(p);
  if ( err == -1 ) {
    perror("nix_build: pipe");
    return NULL;
  }

  pid = fork();
  if ( pid == 0 ) {
    close(p[0]);

    dup2(p[1], STDOUT_FILENO);
    close(STDIN_FILENO);

    execlp("nix-build", "nix-build", "<nixpkgs>", "-A", pkg_name, "--no-out-link", NULL);
    perror("execlp(nix-build)");
    exit(1);
  } else {
    int sts;
    char path[PATH_MAX], *ret;

    close(p[1]);

    // Parent
    err = waitpid(pid, &sts, 0);
    if ( err < 0 ) {
      close(p[0]);
      perror("nix_build: waitpid");
      return NULL;
    } else if ( sts != 0 ) {
      close(p[0]);
      fprintf(stderr, "nix-build returns error %d\n", sts);
      return NULL;
    }

    err = read(p[0], path, PATH_MAX);
    if ( err == -1 ) {
      perror("nix_build: read");
      close(p[0]);
      return NULL;
    }
    path[strnlen(path, sizeof(path)) - 1] = '\0'; // Remove newline

    close(p[0]);

    ret = malloc(strnlen(path, sizeof(path)) + strlen(suffix) + 2);
    snprintf(ret, strnlen(path, sizeof(path)) + strlen(suffix) + 2,
             "%s/%s", path, suffix);
    return ret;
  }
}

void appconf_init(struct appconf *ac) {
  ac->ac_conf_dir = NULL;
  ac->ac_iproute_bin = NULL;
  ac->ac_flags = 0;
}

int appconf_parse_options(struct appconf *ac, int argc, char **argv) {
  int help_flag = 0, option_index = 0, err;
  struct option long_options[] = {
    { "help", no_argument, &help_flag, 1 },
    { "conf-dir", required_argument, 0, 'c' },
    { "iproute", required_argument, 0, 'I' },
    { "valgrind", no_argument, 0, VALGRIND_FLAG },
    { 0, 0, 0, 0 }
  };

  while ( 1 ) {
    err = getopt_long(argc, argv, "hc:", long_options, &option_index);
    if ( err == -1 ) break;

    switch ( err ) {
    default: case 0: break;

    case VALGRIND_FLAG:
      ac->ac_flags |= AC_FLAG_VALGRIND_COMPAT;
      break;

    case 'h':
      help_flag = 1;
      break;

    case 'c':
      ac->ac_conf_dir = optarg;
      break;

    case 'I':
      ac->ac_iproute_bin = optarg;
      break;
    }
  }

  if ( help_flag ) {
    usage(NULL);
    return -1;
  } else {
    return appconf_validate(ac, 1);
  }
}

int appconf_validate(struct appconf *ac, int do_debug) {
  if ( !ac->ac_conf_dir ) {
    usage("No configuration directory provided");
    return -1;
  }

  if ( !ac->ac_iproute_bin ) {
    // Attempt to get iproute information using nix-build
    ac->ac_iproute_bin = nix_build("iproute", "bin/ip");
    if ( !ac->ac_iproute_bin ) {
      fprintf(stderr, "Could not build iproute via nix\n");
      return -1;
    }
  }

  if ( do_debug ) {
    fprintf(stderr, "Using %s as configuration directory\n", ac->ac_conf_dir);
    fprintf(stderr, "Using %s as iproute path\n", ac->ac_iproute_bin);
  }

  return 0;
}

