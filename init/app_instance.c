#define _XOPEN_SOURCE 600

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <linux/prctl.h>

#include "init_proto.h"
#include "init_common.h"
#include "util.h"

#define START_SCRIPT_PATH "/app/start"
#define HC_SCRIPT_PATH    "/app/hc"

extern char **environ;

char *g_persona_id;
char *g_app_url;
char *g_nix_closure;

pid_t g_start_pid = 0;
pid_t g_hc_pid = 0;
int g_hc_retries = 0; // The number of times the health check errored
sig_atomic_t g_alarm_rung = 0; // Set to 1 on SIGALRM

struct host {
  const char *domain;
  const char *target;
  DLIST(struct host) ls;
};

DLIST_HEAD(struct host) g_hosts;

enum {
  NOT_STARTED,
  STARTING,
  HC_HEALTHY,
  HC_ERRORING
} g_status;

// Run the health check script every 30 seconds
#define HEALTH_CHECK_INTERVAL 30
#define HC_ERR_AND_FIXED_STS  128
#define HC_MAX_RETRIES        7

void dbg_printf(const char *format, ...)
  __attribute__ ((format (printf, 1, 2)));

void dbg_printf(const char *format, ...) {
  va_list ap;

  va_start(ap, format);
  fprintf(stderr, "[%s for %s] ", g_app_url, g_persona_id);
  vfprintf(stderr, format, ap);
  va_end(ap);
}

void update_hosts() {
  struct host *h, *tmp;
  FILE *f;

  f = fopen("/run/hosts.tmp", "wt");
  if ( !f ) {
    dbg_printf("Error opening /run/hosts.tmp: %s\n", strerror(errno));
    return;
  }

  fprintf(f, "127.0.0.1 localhost\n");
  fprintf(f, "::1 localhost\n");
  fprintf(f, "127.0.0.1 %s.kite.local\n", g_app_url);
  fprintf(f, "::1 %s.kite.local\n", g_app_url);

  DLIST_ITER(&g_hosts, ls, h, tmp) {
    fprintf(f, "%s %s.kite.local\n", h->target, h->domain);
  }

  fclose(f);

  if ( rename("/run/hosts.tmp", "/run/hosts") < 0 ) {
    perror("update_hosts: rename(\"/run/hosts.tmp\", \"/run/hosts\")");
  }
}

int modhost(int dir, const char *dom, size_t dom_sz, const char *tgt, size_t tgt_sz) {
  struct host *h, *tmp;
  int found = 0;

  DLIST_ITER(&g_hosts, ls, h, tmp) {
    if ( strncmp(h->domain, dom, dom_sz) == 0 ) {
      found = 1;
      if ( dir < 0 ) {
        DLIST_REMOVE(&g_hosts, ls, h);
        free(h);
      } else {
        char *new_tgt;

        new_tgt = realloc((char *) h->target, tgt_sz + 1);
        if ( !new_tgt ) {
          dbg_printf("Could not reallocate target\n");
          return -1;
        }

        memcpy(new_tgt, tgt, tgt_sz);
        new_tgt[tgt_sz] = '\0';
        h->target = new_tgt;
      }
      break;
    }
  }

  if ( dir >= 0 && !found ) {
    char *new_dom, *new_tgt;
    // Add a new entry
    h = malloc(sizeof(*h));
    if ( !h ) {
      dbg_printf("Could not allocate host entry\n");
      return -1;
    }

    DLIST_ENTRY_CLEAR(&h->ls);

    h->domain = new_dom = malloc(dom_sz + 1);
    if ( !new_dom ) {
      free(h);
      dbg_printf("Could not allocate new domain\n");
      return -1;
    }

    h->target = new_tgt = malloc(tgt_sz + 1);
    if ( !new_tgt ) {
      free(new_dom);
      free(h);
      dbg_printf("Could not allocate new target\n");
      return -1;
    }

    memcpy(new_dom, dom, dom_sz);
    new_dom[dom_sz] = '\0';

    memcpy(new_tgt, tgt, tgt_sz);
    new_tgt[tgt_sz] = '\0';

    DLIST_INSERT(&g_hosts, ls, h);
  }

  return found;
}

// Perform the run stork init command
pid_t do_run(struct stkinitmsg *pkt, int sz, int *fds, int nfds, int *waitfd) {
  char *args, *end;
  char **argv = NULL, **envv = NULL;
  int i, err, fdix = 0, fstdin = -1, fstdout = -1, fstderr = -1, cur_envc = 0;
  pid_t child_pid, wait_pid;

  int kite_pipe[2], wait_pipe[2];

  for ( ; environ[cur_envc]; ++cur_envc);

  args = STK_ARGS(pkt);
  end = ((char *) pkt) + sz;

  if ( pkt->un.run.argc <= 1 ) { errno = EINVAL; goto err; }

  argv = malloc(sizeof(char *) * (pkt->un.run.argc + 1));
  if ( !argv ) goto err;

  envv = malloc(sizeof(char *) * (cur_envc + pkt->un.run.envc + 1));
  if ( !envv ) goto err;

  for ( i = 0; i < pkt->un.run.argc; ++i ) {
    if ( args >= end ) { errno = EINVAL; goto err; }

    argv[i] = args;
    args += strnlen(args, end - args) + 1;
  }
  argv[i] = NULL;

  memcpy(envv, environ, sizeof(char *) * cur_envc);

  for ( i = cur_envc; (i - cur_envc) < pkt->un.run.envc; ++i ) {
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

  if ( pkt->sim_flags & STK_RUN_FLAG_KITE ) {
    err = pipe(kite_pipe);
    if ( err < 0 ) {
      perror("pipe");
      goto err;
    }
  }

  if ( pkt->sim_flags & STK_RUN_FLAG_WAIT ) {
    err = pipe(wait_pipe);
    if ( err < 0 ) {
      perror("pipe(wait_pipe)");
      goto err;
    }
  }

  if ( pkt->sim_flags & STK_RUN_FLAG_STDIN ) {
    if ( fdix >= nfds ) goto not_enough_fds;
    fstdin = fds[fdix++];
  }
  if ( pkt->sim_flags & STK_RUN_FLAG_STDOUT ) {
    if ( fdix >= nfds ) goto not_enough_fds;
    fstdout = fds[fdix++];
  }
  if ( pkt->sim_flags & STK_RUN_FLAG_STDERR ) {
    if ( fdix >= nfds ) goto not_enough_fds;
    fstderr = fds[fdix++];
  }

  child_pid = fork();
  if ( child_pid < 0 ) goto err;
  else if ( child_pid == 0 ) {
    int i;
    sigset_t unblocked;
    sigfillset(&unblocked);

    if ( pkt->sim_flags & STK_RUN_FLAG_KITE )
      close(kite_pipe[0]);

    dbg_printf("Going to run");
    for ( i = 0; i < pkt->un.run.argc; ++i )
      fprintf(stderr, " %s", argv[i]);
    fprintf(stderr, "\n");

    close(COMM);
    if ( pkt->sim_flags & STK_RUN_FLAG_KITE ) {
      err = dup2(kite_pipe[1], COMM);
      if ( err < 0 ) {
        perror("dup2(kite_pipe[1], COMM)");
        exit(EXIT_FAILURE);
      }

      close(kite_pipe[1]);
    }

    if ( sigprocmask(SIG_UNBLOCK, &unblocked, NULL) < 0 ) {
      perror("sigprocmask SIG_BLOCK SIGCHLD");
      exit(EXIT_FAILURE);
    }

    if ( fstdin >= 0 ) {
      if ( dup2(fstdin, STDIN_FILENO) < 0 ) {
        perror("dup2(fstdin, STDIN_FILENO)");
        exit(EXIT_FAILURE);
      }
    }
    if ( fstdout >= 0 ) {
      if ( dup2(fstdout, STDOUT_FILENO) < 0 ) {
        perror("dup2(fstdout, STDOUT_FILENO)");
        exit(EXIT_FAILURE);
      }
    }
    if ( fstderr >= 0 ) {
      if ( dup2(fstderr, STDERR_FILENO) < 0 ) {
        perror("dup2(fstderr, STDERR_FILENO)");
        exit(EXIT_FAILURE);
      }
    }

    for ( i = 0; i < nfds; ++i ) {
      if ( i != STDIN_FILENO &&
           i != STDOUT_FILENO &&
           i != STDERR_FILENO ) {
        close(fds[i]);
      }
    }

    if ( pkt->sim_flags & STK_RUN_FLAG_WAIT ) {
      struct sigaction new_sigchld;
      new_sigchld.sa_flags = SA_RESTART | SA_NOCLDSTOP;
      new_sigchld.sa_handler = SIG_DFL;

      if ( sigaction(SIGCHLD, &new_sigchld, 0) < 0 ) {
        perror("sigaction SIGCHLD");
        exit(EXIT_FAILURE);
      }

      close(wait_pipe[0]);

      wait_pid = child_pid;
      child_pid = fork();
      if ( child_pid < 0 ) {
        perror("fork for STK_RUN_FLAG_WAIT");
        exit(EXIT_FAILURE);
      } else if ( child_pid > 0 ) {
        int child_sts;

        // This is the parent
        do {
          err = waitpid(child_pid, &child_sts, 0);
        } while ( err < 0 && errno == EINTR );

        if ( err < 0 ) {
          perror("waitpid");
          exit(EXIT_FAILURE);
        }

        err = write(wait_pipe[1], &child_sts, sizeof(child_sts));
        if ( err < 0 ) {
          perror("write(wait_pipe[1]");
          exit(EXIT_FAILURE);
        }

        exit(child_sts);
      } else
        close(wait_pipe[1]);
    }

    execve(argv[0], argv+1, envv);
    perror("execve");
    exit(EXIT_FAILURE);
  } else {
    uint8_t sts;

    if ( pkt->sim_flags & STK_RUN_FLAG_KITE )
      close(kite_pipe[1]);
    if ( pkt->sim_flags & STK_RUN_FLAG_WAIT ) {
      close(wait_pipe[1]);
      *waitfd = wait_pipe[0];
    } else
      *waitfd = -1;

    dbg_printf("launched with pid %d\n", child_pid);

    if ( fstdin > 0 ) close(fstdin);
    if ( fstdout > 0 ) close(fstdout);
    if ( fstderr > 0 ) close(fstderr);

    if ( pkt->sim_flags & STK_RUN_FLAG_KITE ) {
      err = read(kite_pipe[0], &sts, 1);
      if ( err != 1 ) {
        perror("read(kite_pipe[0])");
      }

      close(kite_pipe[0]);
    }
  }

 done:
  free(argv);
  free(envv);

  return child_pid;

 not_enough_fds:
  dbg_printf("Not enough file descriptors in init message (got %d)\n", nfds);

 err:
  child_pid = -errno;
  goto done;
}

void run_start_script() {
  pid_t child = vfork();
  if ( child == 0 ) {
    execl(START_SCRIPT_PATH, "start", g_persona_id, NULL);
    exit(2);
  } else {
    fprintf(stderr, "started script with pid %d\n", child);
    g_status = STARTING;
    g_start_pid = child;
  }
}

void do_healthcheck() {
  if ( g_status == HC_HEALTHY || g_status == HC_ERRORING ) {
    pid_t child = vfork();
    if ( child < 0 ) {
      perror("vfork");
      exit(4);
    } else if ( child == 0 ) {
      execl(HC_SCRIPT_PATH, "hc", g_persona_id, NULL);
      exit(2);
    } else {
      g_hc_retries++;
      g_hc_pid = child;
    }
  }
}

void set_alarm() {
  alarm(HEALTH_CHECK_INTERVAL);
}

void app_instance_sigalrm_handler(int sig) {
  g_alarm_rung = 1;
}

void app_instance_sigchld_handler(int sig) {
  int saved_errno = errno;
  pid_t pid;
  int sts;

  static const char sig_msg[] = "App instance SIGCHLD";
  write(STDERR_FILENO, sig_msg, strlen(sig_msg));

  do {
    pid = waitpid(-1, &sts, WNOHANG);
    if ( g_start_pid != 0 && pid == g_start_pid ) {
      if ( sts == 0 ) {
        set_alarm();
        g_status = HC_HEALTHY;
      } else {
        static const char exit_msg[] = "App instance init exiting because start script returned error\n";
        write(STDERR_FILENO, exit_msg, strlen(exit_msg));
        exit(sts);
      }
    } else if ( g_hc_pid != 0 && pid == g_hc_pid ) {
      g_hc_pid = 0;
      if ( sts == 0 ) {
        g_status = HC_HEALTHY;
        g_hc_retries = 0;
      } else if ( sts == HC_ERR_AND_FIXED_STS ) {
        if ( g_status == HC_ERRORING && g_hc_retries >= HC_MAX_RETRIES ) {
          static const char exit_msg[] = "App instance exiting because health check had to fix container too many times\n";
          write(STDERR_FILENO, exit_msg, strlen(exit_msg));
          exit(sts);
        }
        g_status = HC_ERRORING;
      } else {
        static const char exit_msg[] = "App instance exiting because health check fails\n";
        write(STDERR_FILENO, exit_msg, strlen(exit_msg));
        exit(sts);
      }
    }
  } while ( pid > 0 );

  errno = saved_errno;
}

void setup_custom_signals() {
  struct sigaction sa;
  sa.sa_handler = &app_instance_sigchld_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
  if ( sigaction(SIGCHLD, &sa, 0) == -1 ) {
    perror("sigaction(SIGCHLD, ...)");
    exit(1);
  }

  sa.sa_handler = &app_instance_sigalrm_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  if ( sigaction(SIGALRM, &sa, 0) == -1 ) {
    perror("sigaction(SIGALRM, ...)");
    exit(1);
  }
}

static int clean_tmp_ent(const char *path, struct stat *info,
                         int flags, struct FTW *d) {
  int err;

  if ( strcmp(path, "/tmp") == 0 ) return 0;

  if ( flags == FTW_DP ) {
    err = rmdir(path);
    if ( err < 0 ) {
      fprintf(stderr, "Could not delete %s: %s\n", path, strerror(errno));
    }
  } else if ( flags == FTW_DNR ) {
    fprintf(stderr, "Could not read directory %s\n", path);
  } else {
    err = unlink(path);
    if ( err < 0 ) {
      fprintf(stderr, "Could not delete %s: %s\n", path, strerror(errno));
    }
  }
  return 0;
}

static void clear_tmp() {
  int err = nftw("/tmp", clean_tmp_ent, PATH_MAX, FTW_CHDIR | FTW_DEPTH | FTW_MOUNT | FTW_PHYS);
  if ( err < 0 ) {
    perror("clear_tmp: nftw");
  } else if ( err > 0 ) {
    fprintf(stderr, "clear_tmp: clean_tmp_ent returned %d\n", err);
  }
}

void usage() {
  fprintf(stderr, "app-instance-init - stork init process for app instance containers\n");
  fprintf(stderr, "usage: app-instance-init <persona-id> <app-name> <app-domain>\n");
}

int main(int argc, char **argv) {
  char *buf;
  struct stkinitmsg *pkt;
  int n;
  int8_t sts = 1;

  if ( argc < 4 ) {
    usage();
    return 1;
  }

  DLIST_INIT(&g_hosts);

  g_persona_id = argv[1];
  g_app_url = argv[2];
  g_nix_closure = argv[3];

  g_status = NOT_STARTED;
  fcntl(COMM, F_SETFD, FD_CLOEXEC);

  dbg_printf("starting\n");

  close_all_files();

  dbg_printf("closed all open files\n");

  dbg_printf("chroot to %s\n", g_nix_closure);

  if ( chroot(g_nix_closure) < 0 ) {
    perror("app_instance_init: chroot");
    return 2;
  }

  dbg_printf("clearing /tmp\n");
  clear_tmp();
  update_hosts();

  // Set cwd to /kite
  if ( chdir("/kite/") < 0 ) {
    perror("app_instance_init: chdir");
    return 3;
  }

  dbg_printf("Changed directory to /kite\n");

  setup_signals();
  setup_custom_signals();

  // The app instance init file needs to run and poll the application
  // instance. We launch the application by running the 'start'
  // script. If it returns an error, we immediately abort.
  //
  // We wait asynchronously for the start script to report
  // success. Once the start script does report success, we
  // periodically (every 15-30 seconds) verify that our service is
  // healthy by running the health check script.
  //
  // The health check script is run asynchronously. It ought to check
  // that all services are running, and launch any that are acting
  // improperly. It should return 0 if everything was healthy, or 128 if
  // a fix was made. Any other error number is considered an error.
  //
  // If the health check script returns an error other than 128, the
  // container is brought down and an error is logged.
  //
  // If the health check script returns 128, then we are marked in the
  // 'ERRORING' state. If further health checks continue to return
  // 128, then we will end up closing the container down after 7
  // retries.
  //
  // If the health check script returns 0, we put ourselves in the
  // healthy state and continue processing.
  //
  // The health check timeout is achieved through the use of alarm(2)
  // function.

  run_start_script();

  buf = malloc(STK_MAX_PKT_SZ);
  if ( !buf ) {
    perror("malloc(STK_MAX_PKT_SZ)");
    return 1;
  }

  pkt = (struct stkinitmsg *)buf;
  n = send(COMM, &sts, 1, 0);
  if ( n == -1 ) {
    perror("send");
    return 1;
  }

  while ( 1 ) {
    pid_t child_pid;
    char cbuf[128];
    int fds[3], nfds = 0, i, waitfd = -1, err;
    struct cmsghdr *cmsg;
    struct iovec iov = { .iov_base = buf,
                         .iov_len = STK_MAX_PKT_SZ };
    struct msghdr msg = {
      .msg_flags = 0,
      .msg_name = NULL,
      .msg_namelen = 0,

      .msg_iov = &iov,
      .msg_iovlen = 1,

      .msg_control = cbuf,
      .msg_controllen = sizeof(cbuf)
    };

    n = recvmsg(COMM, &msg, 0);
    if ( n == 0 ) break;
    else if ( n == -1 ) {
      if ( errno == EAGAIN || errno == EINTR ) {
        if ( g_alarm_rung ) {
          g_alarm_rung = 0;
          do_healthcheck();
          set_alarm();
        }
        continue;
      } else {
        perror("recv");
        return 1;
      }
    }

    if ( n < sizeof(*pkt) ) {
      dbg_printf("Packet is too small %d < %zu\n", n, sizeof(*pkt));
      continue;
    }

    switch ( pkt->sim_req ) {
    case STK_REQ_RUN:
      for ( cmsg = CMSG_FIRSTHDR(&msg); cmsg;
            cmsg = CMSG_NXTHDR(&msg, cmsg) ) {
        if ( cmsg->cmsg_level == SOL_SOCKET &&
             cmsg->cmsg_type == SCM_RIGHTS &&
             (cmsg->cmsg_len % sizeof(*fds)) == 0&&
             cmsg->cmsg_len <= CMSG_LEN(sizeof(fds)) ) {
          nfds = (cmsg->cmsg_len - sizeof(struct cmsghdr)) / sizeof(*fds);
          memcpy(fds, CMSG_DATA(cmsg), sizeof(*fds) * nfds);
        }
      }

      child_pid = do_run(pkt, n, fds, nfds, &waitfd);
      msg.msg_flags = 0;
      msg.msg_name = NULL;
      msg.msg_namelen = 0;
      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;
      iov.iov_base = &child_pid;
      iov.iov_len = sizeof(child_pid);

      if ( waitfd >= 0 ) {
        msg.msg_control = cbuf;
        msg.msg_controllen = CMSG_SPACE(sizeof(int));

        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &waitfd, sizeof(waitfd));
      } else {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
      }

      do {
        n = sendmsg(COMM, &msg, 0);
      } while ( n < 0 && errno == EINTR );

      if ( n < 0 ) {
        perror("send");
        return 1;
      }

      if ( waitfd >= 0 )
        close(waitfd);

      break;

    case STK_REQ_MOD_HOST_ENTRY:
      if ( n < sizeof(*pkt) + pkt->un.modhost.dom_len + pkt->un.modhost.tgt_len ) {
        dbg_printf("Not enough data in mod host (%d, %ld, %d, %d)\n",
                   n, sizeof(*pkt) + pkt->un.modhost.dom_len + pkt->un.modhost.tgt_len,
                   pkt->un.modhost.dom_len, pkt->un.modhost.tgt_len);
        err = -1;
      } else {
        err = modhost(pkt->un.modhost.dir,
                      pkt->after, pkt->un.modhost.dom_len,
                      pkt->after + pkt->un.modhost.dom_len,
                      pkt->un.modhost.tgt_len);
      }

      do {
        n = send(COMM, &err, sizeof(err), 0);
      } while ( n < 0 && errno == EINTR );

      if ( n < 0 ) {
        perror("send");
        return 1;
      }

      update_hosts();

      break;

    default:
      dbg_printf("Invalid init req: %d\n", pkt->sim_req);
    }

    for ( i = 0; i < nfds; ++i )
      close(fds[i]);
  }
}
