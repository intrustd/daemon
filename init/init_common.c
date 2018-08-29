#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <linux/prctl.h>

#include "init_common.h"

void sigchld_handler(int sig) {
  int saved_errno = errno;
  while ( waitpid((-1), 0, WNOHANG) > 0 ) { }
  errno = saved_errno;
}

void sigpipe_handler(int sig) {
  static const char msg[] = "Received SIGPIPE\n";
  write(STDERR_FILENO, msg, strlen(msg));

  exit(2);
}

void sigterm_handler(int sig) {
  static const char msg[] = "Received SIGPIPE\n";
  write(STDERR_FILENO, msg, strlen(msg));

  exit(2);
}

void sighup_handler(int sig) {
  static const char msg[] = "Exiting due to storkd exit\n";
  write(STDERR_FILENO, msg, strlen(msg));

  exit(0);
}

void setup_signals() {
  // Set up SIGCHLD handler
  struct sigaction sa;
  sa.sa_handler = &sigchld_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
  if ( sigaction(SIGCHLD, &sa, 0) == -1 ) {
    perror("sigaction(SIGCHLD, ...)");
    exit(1);
  }

  sa.sa_handler = &sigpipe_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  if ( sigaction(SIGPIPE, &sa, 0) == -1 ) {
    perror("sigaction(SIGPIPE, ...)");
    exit(1);
  }

  sa.sa_handler = &sigterm_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  if ( sigaction(SIGTERM, &sa, 0) == -1 ) {
    perror("sigaction(SIGTERM, ...)");
    exit(1);
  }

  sa.sa_handler = &sighup_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  if ( sigaction(SIGHUP, &sa, 0) == -1 ) {
    perror("sigaction(SIGHUP, ...)");
    exit(1);
  }

  // Set SIGPIPE to be delivered on parental death
  if ( prctl(PR_SET_PDEATHSIG, SIGHUP) == -1 ) {
    perror("prctl PR_SET_PDEATHSIG");
    exit(1);
  }
}

void close_all_files() {
  int max_fd = sysconf(_SC_OPEN_MAX), i;

  for ( i = 4; i < max_fd; ++i )
    close(i);
}
