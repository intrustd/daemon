#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <linux/prctl.h>

#include "init_common.h"
#include "init_proto.h"

char *g_persona_id;

pid_t do_run(struct appinitmsg *pkt, int sz) {
  char *args, *end;
  char **argv = NULL, **envv = NULL;
  int i, err;
  pid_t child_pid;

  int appd_pipe[2];

  args = APPINIT_ARGS(pkt);
  end = ((char *) pkt) + sz;

  if ( pkt->un.run.argc <= 1 ) { errno = EINVAL; goto err; }

  argv = malloc(sizeof(char *) * (pkt->un.run.argc + 1));
  if ( !argv ) goto err;

  envv = malloc(sizeof(char *) * (pkt->un.run.envc + 1));
  if ( !envv ) goto err;

  for ( i = 0; i < pkt->un.run.argc; ++i ) {
    if ( args >= end ) { errno = EINVAL; goto err; }

    argv[i] = args;
    args += strnlen(args, end - args) + 1;
  }
  argv[i] = NULL;

  for ( i = 0; i < pkt->un.run.envc; ++i ) {
    if ( args >= end ) goto err;

    envv[i] = args;
    args += strnlen(args, end - args) + 1;
  }
  envv[i] = NULL;

  if ( args > end ) {
    errno = EINVAL;
    fprintf(stderr, "Could not parse commands correctly\n");
    goto err;
  }

  fprintf(stderr, "[Persona %s] Running command\n", g_persona_id);

  if ( pkt->aim_flags & APPINIT_RUN_FLAG_INTRUSTD_INIT ) {
    err = pipe(appd_pipe);
    if ( err < 0 ) {
      perror("pipe");
      goto err;
    }
  }

  child_pid = vfork();
  if ( child_pid < 0 ) goto err;
  else if ( child_pid == 0 ) {
    if ( pkt->aim_flags & APPINIT_RUN_FLAG_INTRUSTD_INIT )
      close(appd_pipe[0]);

    fprintf(stderr, "[Persona %s] Going to run %s\n", g_persona_id, argv[0]);

    close(COMM);
    if ( pkt->aim_flags & APPINIT_RUN_FLAG_INTRUSTD_INIT ) {
      err = dup2(appd_pipe[1], COMM);
      if ( err < 0 ) {
        perror("dup2(appd_pipe[1], COMM)");
        exit(EXIT_FAILURE);
      }

      close(appd_pipe[1]);
    }

    execve(argv[0], argv+1, envv);
    perror("execve");
    exit(EXIT_FAILURE);
  } else {
    uint8_t sts;

    if ( pkt->aim_flags & APPINIT_RUN_FLAG_INTRUSTD_INIT )
      close(appd_pipe[1]);

    fprintf(stderr, "[Persona %s] launched with pid %d\n", g_persona_id, child_pid);

    if ( pkt->aim_flags & APPINIT_RUN_FLAG_INTRUSTD_INIT ) {
      err = read(appd_pipe[0], &sts, 1);
      if ( err != 1 ) {
        perror("read(appd_pipe[0])");
      }

      close(appd_pipe[0]);
    }
  }

 done:
  free(argv);
  free(envv);

  return child_pid;

 err:
  child_pid = -errno;
  goto done;
}

void usage() {
  fprintf(stderr, "persona-init - intrustd init process for persona containers\n");
  fprintf(stderr, "usage: persona-init <persona-id>\n");
}

int main(int argc, char **argv) {
  char *buf;
  struct appinitmsg *pkt;
  uint8_t sts = 1;
  int n, ret;
  pid_t our_pid = getpid(), child_pid;

  if ( argc < 2 ) {
    usage();
    return 1;
  }

  g_persona_id = argv[1];
  fcntl(COMM, F_SETFD, FD_CLOEXEC);

  fprintf(stderr, "[Persona %s] starting\n", g_persona_id);

  close_all_files();

  fprintf(stderr, "[Persona %s] closed all open files\n", g_persona_id);

  setup_signals();

  fprintf(stderr, "[Persona %s] set up signals\n", g_persona_id);

  buf = malloc(APPINIT_MAX_PKT_SZ);
  if ( !buf ) {
    perror("malloc(APPINIT_MAX_PKT_SZ)");
    return 1;
  }

  pkt = (struct appinitmsg *)buf;
  n = send(COMM, &sts, 1, 0);
  if ( n == -1 ) {
    perror("send");
    return 1;
  }

  // Continuously read from COMM socket
  while ( 1 ) {

    n = recv(COMM, buf, APPINIT_MAX_PKT_SZ, 0);
    if ( n == 0 ) break;

    if ( n == -1 ) {
      if ( errno == EAGAIN || errno == EINTR )
        continue;
      else {
        perror("recv");
        return 1;
      }
    }

    if ( n < sizeof(*pkt) ) {
      fprintf(stderr, "[Persona %s] Packet is too small %d < %lu\n", g_persona_id, n, sizeof(*pkt));
    }

    switch ( pkt->aim_req ) {
    case APPINIT_REQ_RUN:
      child_pid = do_run(pkt, n);
      do {
        n = send(COMM, &child_pid, sizeof(child_pid), 0);
      } while ( n == -1 && errno == EINTR );

      if ( n == -1 ) {
        perror("send");
        return 1;
      }

      break;
    case APPINIT_REQ_KILL:
      fprintf(stderr, "Killing process %d with signal %d\n", pkt->un.kill.which, pkt->un.kill.sig);
      ret = kill(pkt->un.kill.which, pkt->un.kill.sig);
      if ( ret < 0 ) {
        ret = -errno;
        perror("persona_init: kill");
      }

      do {
        n = send(COMM, &ret, sizeof(ret), 0);
      } while ( n == -1 && errno == EINTR );

      if ( n == -1 ) {
        perror("send");
        return 1;
      }

      break;
    default:
      fprintf(stderr, "[Persona %s] Invalid init req: %d\n", g_persona_id, pkt->aim_req);
    };
  }

  return 0;
}
