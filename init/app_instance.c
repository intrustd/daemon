#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <linux/prctl.h>

#include "init_proto.h"
#include "init_common.h"

#define START_SCRIPT_PATH "/app/start"
#define HC_SCRIPT_PATH    "/app/hc"

char *g_persona_id;
char *g_app_url;
char *g_nix_closure;

pid_t g_start_pid = 0;
pid_t g_hc_pid = 0;
int g_hc_retries = 0; // The number of times the health check errored
sig_atomic_t g_alarm_rung = 0; // Set to 1 on SIGALRM

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

void run_start_script() {
  pid_t child = vfork();
  if ( child == 0 ) {
    execl(START_SCRIPT_PATH, "start", g_persona_id, NULL);
    exit(2);
  } else {
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

  // Set cwd to /stork
  if ( chdir("/stork/") < 0 ) {
    perror("app_instance_init: chdir");
    return 3;
  }

  dbg_printf("Changed directory to /stork\n");

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
    n = recv(COMM, buf, STK_MAX_PKT_SZ, 0);
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

      if ( n < sizeof(*pkt) ) {
        dbg_printf("Packet is too small %d < %lu\n", n, sizeof(*pkt));
      }

      switch ( pkt->sim_req ) {
      case STK_REQ_RUN:
        dbg_printf("Run not implemented\n");
        break;
      default:
        dbg_printf("Invalid init req: %d\n", pkt->sim_req);
      }
    }
  }
}
