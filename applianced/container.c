#define _GNU_SOURCE
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "container.h"
#include "util.h"
#include "init_proto.h"
#include "process.h"

#define OP_CONTAINER_WAITER_COMPLETE EVT_CTL_CUSTOM

#define OP_CONTAINER_TIMES_OUT EVT_CTL_CUSTOM
#define OP_CONTAINER_CHECK_PERM (EVT_CTL_CUSTOM + 1)

struct containerinit {
  int            ci_bridge_port;
  struct in_addr ci_ip;
};

struct containerwaiter {
  struct pssub cw_process;
  int          cw_init_comm;
  struct qdevtsub *cw_completion_evt;
};

static void containerevtfn(struct eventloop *el, int op, void *arg);
static int containerpermfn(struct arpentry *ae, int op, void *arg, ssize_t sz);

static int container_start_child(void *c_);

static void ctrwaiterevtfn(struct eventloop *el, int op, void *arg);

static int g_child_sync_pipes[] = { -1, -1 }; // No need for synchronization because of fork()

void container_clear(struct container *c) {
  c->c_bridge = NULL;
  c->c_flags = 0;
  c->c_init_process = -1;
  c->c_init_comm = -1;
  c->c_bridge_port = -1;
  memset(&c->c_ip, 0, sizeof(c->c_ip));
  memset(c->c_mac, 0, sizeof(c->c_mac));
  c->c_control = NULL;
  c->c_running_refs = 0;
}

int container_init(struct container *c, struct brstate *br, containerctlfn cfn, uint32_t flags) {
  container_clear(c);

  if ( pthread_mutex_init(&c->c_mutex, NULL) < 0 )
    return -1;

  c->c_bridge = br;
  c->c_control = cfn;
  c->c_flags = flags;

  bridge_allocate(br, &c->c_ip, &c->c_bridge_port);

  timersub_init_default(&c->c_timeout, OP_CONTAINER_TIMES_OUT, containerevtfn);

  return 0;
}

void container_release(struct container *c) {
  int is_running;
  if ( c->c_bridge ) {
    SAFE_MUTEX_LOCK(&c->c_mutex);
    is_running = c->c_running_refs > 0;
    pthread_mutex_unlock(&c->c_mutex);

    if ( is_running ) {
      fprintf(stderr, "container_release: called on running container\n");
      abort();
    }

    pthread_mutex_destroy(&c->c_mutex);
  }
}

int container_is_running(struct container *c) {
  if ( pthread_mutex_lock(&c->c_mutex) == 0 ) {
    int ret = c->c_running_refs > 0;
    pthread_mutex_unlock(&c->c_mutex);
    return ret;
  } else
    return 0;
}

int container_ensure_running(struct container *c, struct eventloop *el) {
  if ( pthread_mutex_lock(&c->c_mutex) == 0 ) {
    int ret = 0;
    if ( c->c_running_refs == 0 ) {
      fprintf(stderr, "clear container timeout start\n");
      eventloop_cancel_timer(el, &c->c_timeout);
      fprintf(stderr, "clear container timeout done\n");

      if ( c->c_init_process < 0 ) {
        ret = container_start(c);
        if ( ret >= 0 )
          c->c_running_refs++;
      } else
        c->c_running_refs++;

      ret = 1;
    } else
      c->c_running_refs++;
    pthread_mutex_unlock(&c->c_mutex);
    return ret;
  } else
    return -1;
}

int container_release_running(struct container *c, struct eventloop *el) {
  if ( pthread_mutex_lock(&c->c_mutex) == 0 ) {
    int ret = 0;
    SAFE_ASSERT( c->c_running_refs > 0 );
    c->c_running_refs--;

    if ( c->c_running_refs == 0 ) {
      if ( c->c_flags & CONTAINER_FLAG_KILL_IMMEDIATELY ) {
        timersub_set_from_now(&c->c_timeout, 0);
      } else {
        timersub_set_from_now(&c->c_timeout, CONTAINER_TIMEOUT);
      }

      eventloop_subscribe_timer(el, &c->c_timeout);
      ret = 1;
    }
    pthread_mutex_unlock(&c->c_mutex);
    return ret;
  } else
    return -1;
}

static void ctrwaiterevtfn(struct eventloop *el, int op, void *arg) {
  struct psevent *pe = arg;
  struct containerwaiter *cw;

  switch ( op ) {
  case OP_CONTAINER_WAITER_COMPLETE:
    cw = STRUCT_FROM_BASE(struct containerwaiter, cw_process, pe->pse_sub);

    fprintf(stderr, "Container exited with status %d\n", pe->pse_sts);
    close(cw->cw_init_comm);

    if ( cw->cw_completion_evt )
      eventloop_queue(el, cw->cw_completion_evt);

    free(cw);

    break;

  default:
    fprintf(stderr, "ctrwaiterevtfn: unknown op %d\n", op);
  }
}

static void containerevtfn(struct eventloop *el, int op, void *arg) {
  struct qdevent *te;
  struct container *c;
  struct brpermrequest *bpr;

  switch ( op ) {
  case OP_CONTAINER_TIMES_OUT:
    te = (struct qdevent *) arg;
    c = STRUCT_FROM_BASE(struct container, c_timeout, te->qde_timersub);
    if ( pthread_mutex_lock(&c->c_mutex) == 0 ) {
      if ( c->c_running_refs == 0 ) {
        pthread_mutex_unlock(&c->c_mutex);
        container_stop(c, el, NULL);
      } else
        pthread_mutex_unlock(&c->c_mutex);
    }
    return;

  case OP_CONTAINER_CHECK_PERM:
    te = (struct qdevent *) arg;
    bpr = STRUCT_FROM_BASE(struct brpermrequest, bpr_start_event, te->qde_sub);
    c = bpr->bpr_user_data;

    bpr->bpr_sts = c->c_control(c, CONTAINER_CTL_CHECK_PERMISSION, bpr, 0);
    if ( bpr->bpr_sts < 0 ) {
      fprintf(stderr, "containerpermfn: CONTAINER_CTL_CHECK_PERMISSION failed\n");
    }
    eventloop_queue(bpr->bpr_el, &bpr->bpr_finished_event);
    return;

  default:
    fprintf(stderr, "containerevtfn: unknown op %d\n", op);
    return;
  }
}

static int container_setup_sctp(struct container *c) {
  int ret = -1;
  FILE *en;

  en = fopen("/proc/sys/net/sctp/intl_enable", "wt");
  if ( !en ) {
    perror("fopen /proc/sys/net/sctp/intl_enable");
    if ( errno != ENOENT ) {
      ret = -1;
      goto error;
    } else
      fprintf(stderr, "This kernel does not support SCTP interleaving\n");
  } else {
    fprintf(en, "1");
    fclose(en);
    ret = 0;
  }

  en = fopen("/proc/sys/net/sctp/reconf_enable", "wt");
  if ( !en ) {
    perror("fopen /proc/sys/net/sctp/reconf_enable");
    ret = -1;
    goto error;
  } else {
    fprintf(en, "1");
    fclose(en);
    ret = 0;
  }

 error:

  return ret;
}

int container_start(struct container *c) {
  int err, ipc_sockets[2] = { -1, -1 };
  uint8_t sts;
  pid_t child = -1, real_child = -1;
  struct containerinit ci_data;

  err = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, ipc_sockets);
  if ( err < 0 ) {
    perror("container_start: socketpair");
    goto error;
  }

  child = fork();
  if ( child < 0 ) {
    perror("container_start: fork");
    goto error;
  } else if ( child == 0 ) {
    char *child_stack = NULL;
    int yes = 1;
    int clone_flags = CLONE_PARENT | SIGCHLD;
    size_t child_stack_sz = 256 * 1024;

    err = posix_memalign((void **)&child_stack, sysconf(_SC_PAGE_SIZE), child_stack_sz);
    if ( err != 0 ) {
      fprintf(stderr, "container_start: could not allocate stack\n");
      exit(1);
    }

    close(ipc_sockets[0]);
    ipc_sockets[0] = -1;

    err = pipe(g_child_sync_pipes);
    if ( err < 0 ) {
      perror("container_start: pipe");
      exit(1);
    }

    // child process
    err = setns(c->c_bridge->br_userns, CLONE_NEWUSER);
    if ( err < 0 ) {
      perror("container_start: setns");
      exit(1);
    }

    // Because we've forked, writing this does not overwrite the value in the parent process
    c->c_init_comm = ipc_sockets[1];

    if ( c->c_flags & CONTAINER_FLAG_NETWORK_ONLY ) {
      clone_flags |= CLONE_NEWNET | CLONE_NEWUTS;
    } else {
      clone_flags |= CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS |
        CLONE_NEWPID | CLONE_NEWUTS;
    }

    if ( c->c_flags & CONTAINER_FLAG_ENABLE_SCTP ) {
      clone_flags |= CLONE_NEWNS;
    }

    real_child = clone(container_start_child, child_stack + child_stack_sz,
                       clone_flags, (void *)c);
    if ( real_child < 0 ) {
      perror("container_start: clone");
      exit(1);
    }

    close(g_child_sync_pipes[0]);

    err = send(ipc_sockets[1], &real_child, sizeof(real_child), 0);
    if ( err < 0 ) {
      perror("container_start: send");
      exit(1);
    }

    err = write(g_child_sync_pipes[1], &yes, sizeof(yes));
    if ( err < 0 ) {
      perror("container_start: write");
      exit(1);
    }

    exit(0);
  } else {
    int child_sts = 0;

    err = recv(ipc_sockets[0], &real_child, sizeof(real_child), 0);
    if ( err < 0 ) {
      perror("container_start: recv");
      goto error;
    }

    err = waitpid(child, &child_sts, 0);
    if ( err < 0 ) {
      perror("container_start: waitpid");
      goto error;
    }
    child = -1;

    if ( child_sts != 0 ) {
      fprintf(stderr, "container_start: child reported error: %d\n", child_sts);
      goto error;
    }
  }

  if ( real_child < 0 ) {
    fprintf(stderr, "container_start: the child process indicated there was an error\n");
    goto error;
  }

  close(ipc_sockets[1]);
  ipc_sockets[1] = -1;

  ci_data.ci_bridge_port = c->c_bridge_port;
  memcpy(&ci_data.ci_ip, &c->c_ip, sizeof(ci_data.ci_ip));

  err = send(ipc_sockets[0], &ci_data, sizeof(ci_data), 0);
  if ( err < 0 ) {
    perror("container_start: send");
    goto error;
  }

  fprintf(stderr, "container_start: got child id %d... fetching arp\n", real_child);

  // Now receive the arp entry
  err = recv(ipc_sockets[0], &c->c_arp_entry, sizeof(c->c_arp_entry), 0);
  if ( err < 0 || err != sizeof(c->c_arp_entry) ) {
    perror("container_start: recv(&c->c_arp_entry)");
    goto error;
  }
  c->c_arp_entry.ae_ctlfn = containerpermfn;

  err = bridge_add_arp(c->c_bridge, &c->c_arp_entry);
  if ( err < 0 ) {
    fprintf(stderr, "bridge_add_arp failed\n");
    goto error;
  }

  // Finally... wait for init process to start
  err = recv(ipc_sockets[0], &sts, 1, 0);
  if ( err != 1 ) {
    perror("container_start: recv init status");
    goto error;
  }

  fprintf(stderr, "Got init status: %d\n", sts);

  c->c_init_comm = ipc_sockets[0];
  c->c_init_process = real_child;

  return 0;

 error:
  close(ipc_sockets[0]);
  close(ipc_sockets[1]);
  if ( child >= 0 )
    kill(child, SIGKILL);
  if ( real_child >= 0 )
    kill(real_child, SIGKILL);
  return -1;
}

int container_force_stop(struct container *c) {
  int err = 0;
  SAFE_MUTEX_LOCK(&c->c_mutex);
  if ( c->c_init_process > 0 ) {
    err = kill(c->c_init_process, SIGKILL);
    if ( err < 0 ) {
      perror("container_force_stop: kill SIGKILL");
    }
  }
  pthread_mutex_unlock(&c->c_mutex);
  return err;
}

int container_stop(struct container *c, struct eventloop *el, struct qdevtsub *comp_event) {
  // Send SIGTERM message to init process, and create a new timer to
  // ensure the end of this process.
  //
  // Meanwhile, immediately disconnect the veth from the bridge

  int err, ret = 0, port = c->c_bridge_port;

  struct containerwaiter *waiter;

  fprintf(stderr, "container_stop: stopping\n");

  SAFE_MUTEX_LOCK(&c->c_mutex);
  // Refresh the IP address for the container
  //bridge_allocate(c->c_bridge, &c->c_ip, &c->c_bridge_port);

  // Disconnects a port from the bridge
  err = bridge_disconnect_port(c->c_bridge, port, &c->c_arp_entry);
  if ( err < 0 )
    fprintf(stderr, "container_stop: could not disconnect bridge\n");

  // Now send the init process a SIGTERM signal
  waiter = malloc(sizeof(*waiter));
  if ( !waiter ) {
    fprintf(stderr, "container_stop: could not allocate waiter, send SIGKILL to init\n");

    err = kill(c->c_init_process, SIGKILL);
    if ( err < 0 ) {
      ret = -1;
      perror("container_stop: kill SIGKILL");
    }

    err = c->c_control(c, CONTAINER_CTL_ON_SHUTDOWN, NULL, 0);
    if ( err < 0 ) {
      fprintf(stderr, "container_stop: CONTAINER_CTL_ON_SHUTDOWN returned error\n");
      pthread_mutex_unlock(&c->c_mutex);
      return err;
    }

    close(c->c_init_comm);
  } else {
    waiter->cw_init_comm = c->c_init_comm;
    waiter->cw_completion_evt = comp_event;

    pssub_init(&waiter->cw_process, OP_CONTAINER_WAITER_COMPLETE, ctrwaiterevtfn);
    err = pssub_attach(el, &waiter->cw_process, c->c_init_process);
    if ( err < 0 ) {
      ret = -1;
      fprintf(stderr, "container_stop: could not attach to init process\n");

      kill(c->c_init_process, SIGKILL);
      close(c->c_init_comm);
      free(waiter);
    } else {
      err = kill(c->c_init_process, SIGTERM);
      if ( err < 0 ) {
        ret = -1;
        perror("container_stop: kill SIGTERM");
      }
    }
  }

  c->c_init_process = -1;
  c->c_init_comm = -1;
  memset(c->c_mac, 0, sizeof(c->c_mac));

  pthread_mutex_unlock(&c->c_mutex);

  return ret;
}

// Called in the child
static int container_start_child(void *c_) {
  struct container *c = (struct container *)c_;
  int sync, err, argc, netns;
  struct containerinit ci;

  const char *hostname_str = NULL, *init_path_str = NULL;

  const char *argv[32];

  struct arpentry arp_entry;

  memset(argv, 0, sizeof(argv));

  fprintf(stderr, "container_start_child: starting: %d\n", getpid());

  close(g_child_sync_pipes[1]);

  err = read(g_child_sync_pipes[0], &sync, sizeof(sync));
  if ( err < 0 ) {
    perror("container_start_child: read");
    return 1;
  }

  // Receive the setup data on this socket
  err = recv(c->c_init_comm, &ci, sizeof(ci), 0);
  if ( err != sizeof(ci) ) {
    perror("container_start_child: recv");
    return 1;
  }

  // We're in the bridge namespace
  err = bridge_setup_root_uid_gid(c->c_bridge);
  if ( err < 0 ) {
    fprintf(stderr, "could not set root uid gid\n");
    return 1;
  }

  // Get information
  err = c->c_control(c, CONTAINER_CTL_GET_HOSTNAME, (void *) &hostname_str, 0);
  if ( err < 0 ) {
    fprintf(stderr, "Could not get host name\n");
    return 1;
  }

  err = c->c_control(c, CONTAINER_CTL_GET_INIT_PATH, (void *) &init_path_str, 0);
  if ( err < 0 ) {
    fprintf(stderr, "Could not get init path\n");
    return 1;
  }

  fprintf(stderr, "Launching container with init %s\n", init_path_str);

  argv[0] = "init";
  argc = c->c_control(c, CONTAINER_CTL_GET_ARGS, (void *) (argv + 1),
                      (sizeof(argv)/sizeof(argv[0])) - 2);
  if ( argc < 0 ) {
    fprintf(stderr, "Could not get args\n");
    return 1;
  }
  argc += 1;

  if ( (argc + 1) < (sizeof(argv) / sizeof(argv[0])) )
    argv[argc + 1] = NULL;
  else
    argv[sizeof(argv)/sizeof(argv[0]) - 1] = NULL;

  // Set hostname
  fprintf(stderr, "sethostname: %p %s\n", hostname_str, hostname_str);

  err = sethostname(hostname_str, strlen(hostname_str));
  if ( err < 0 ) {
    perror("container_start_child: sethostname");
    return 1;
  }

  err = setdomainname("kite", 4);
  if ( err < 0 ) {
    perror("container_start_child: setdomainname");
    return 1;
  }

  err = bridge_set_up_networking(c->c_bridge);
  if ( err < 0 ) {
    fprintf(stderr, "container_start_child: could not set up bridge networking\n");
    return 1;
  }

  netns = open("/proc/self/ns/net", O_CLOEXEC);
  if ( netns < 0 ) {
    perror("container_start_child: open(/proc/self/ns/net)");
    return 1;
  }

  err = bridge_create_veth_to_ns(c->c_bridge, c->c_bridge_port, netns,
                                 &c->c_ip, "eth0", &arp_entry);
  if ( err < 0 ) {
    fprintf(stderr, "container_start_child: ccould not set up veth\n");
    return 1;
  }

  arp_entry.ae_ctlfn = NULL;
  err = send(c->c_init_comm, &arp_entry, sizeof(arp_entry), 0);
  if ( err < 0 ) {
    perror("container_start_child: send(&arp_entry)");
    return 1;
  }

  memcpy(&c->c_arp_entry, &arp_entry, sizeof(c->c_arp_entry));

  fprintf(stderr, "Done setting up container\n");
//  fprintf(stderr, "Listing devices...\n");
//  err = system("ifconfig -a");
//  fprintf(stderr, "Listing routes\n");
//  err = system("route");

  if ( c->c_flags & CONTAINER_FLAG_ENABLE_SCTP ) {
    fprintf(stderr, "Enable SCTP interleaving\n");

    // Set up various SCTP options
    err = container_setup_sctp(c);
    if ( err < 0 ) {
      fprintf(stderr, "container_setup_sctp: returned error\n");
      return EXIT_FAILURE;
    }
  }

  // Now run container setup
  if ( c->c_control(c, CONTAINER_CTL_DO_SETUP, 0, 0) == -1 ) {
    fprintf(stderr, "Container setup failed\n");
    return EXIT_FAILURE;
  }

  err = dup2(c->c_init_comm, 3);
  if ( err < 0 ) {
    perror("container_start_child: dup2");
    return 1;
  }

  if ( c->c_init_comm != 3 )
    close(c->c_init_comm);

  err = prctl(PR_SET_PDEATHSIG, SIGHUP);
  if ( err < 0 ) {
    perror("container_start_child: prctl");
    return 1;
  }

  fprintf(stderr, "Running %s\n", init_path_str);

  execv(init_path_str, (char *const *) argv);
  perror("execv");

  return EXIT_FAILURE;
}

int container_execute(struct container *c, uint32_t exec_flags, const char *path,
                      const char **argv, const char **envv) {
  struct containerexecinfo info;

  info.cei_flags = exec_flags & ~(CONTAINER_EXEC_ENABLE_WAIT |
                                  CONTAINER_EXEC_REDIRECT_STDIN |
                                  CONTAINER_EXEC_REDIRECT_STDOUT |
                                  CONTAINER_EXEC_REDIRECT_STDERR);
  info.cei_exec = path;
  info.cei_argv = argv;
  info.cei_envv = envv;

  return container_execute_ex(c, &info);
}

int container_execute_ex(struct container *c, struct containerexecinfo *info) {
  char *buf, *out;
  struct stkinitmsg msg;
  size_t buf_size = sizeof(struct stkinitmsg);
  int i = 0, argc = 1, envc = 0, err;

  struct iovec iov;
  struct msghdr skmsg = {
    .msg_flags = 0,
    .msg_name = NULL,
    .msg_namelen = 0,

    .msg_iov = &iov,
    .msg_iovlen = 1,

    .msg_control = NULL,
    .msg_controllen = 0
  };

  buf_size += strlen(info->cei_exec) + 1;

  for ( i = 0; i < CONTAINER_MAX_ARGC && info->cei_argv && info->cei_argv[i]; ++i, ++argc ) {
    buf_size += strlen(info->cei_argv[i]) + 1; // Final NULL byte
  }
  if ( i == CONTAINER_MAX_ARGC ) {
    fprintf(stderr, "container_execute: too many arguments\n");
    return -1;
  }

  for ( i = 0; i < CONTAINER_MAX_ENVC && info->cei_envv && info->cei_envv[i]; ++i, ++envc ) {
    buf_size += strlen(info->cei_envv[i]) + 1;
  }
  if ( i == CONTAINER_MAX_ENVC ) {
    fprintf(stderr, "container_execute: too many envirorment variables\n");
    return -1;
  }

  if ( buf_size >= STK_MAX_PKT_SZ ) {
    fprintf(stderr, "container_execute: packet exceeds bounds\n");
    return -1;
  }

  buf = alloca(buf_size);
  assert(buf);

  msg.sim_req = STK_REQ_RUN;
  msg.sim_flags = 0;

  if ( info->cei_flags & CONTAINER_EXEC_WAIT_FOR_KITE )
    msg.sim_flags |= STK_RUN_FLAG_KITE;

  if ( info->cei_flags & (CONTAINER_EXEC_REDIRECT_STDIN |
                          CONTAINER_EXEC_REDIRECT_STDOUT |
                          CONTAINER_EXEC_REDIRECT_STDERR) ) {

    int nfds = 0, fds[3];
    struct cmsghdr *cmsg;

    fprintf(stderr, "Adding redirection fds\n");

    if ( info->cei_flags & CONTAINER_EXEC_REDIRECT_STDIN ) {
      fds[nfds++] = info->cei_stdin_fd;
      msg.sim_flags |= STK_RUN_FLAG_STDIN;
    }
    if ( info->cei_flags & CONTAINER_EXEC_REDIRECT_STDOUT ) {
      fds[nfds++] = info->cei_stdout_fd;
      msg.sim_flags |= STK_RUN_FLAG_STDOUT;
    }
    if ( info->cei_flags & CONTAINER_EXEC_REDIRECT_STDERR ) {
      fds[nfds++] = info->cei_stderr_fd;
      msg.sim_flags |= STK_RUN_FLAG_STDERR;
    }

    skmsg.msg_controllen += CMSG_SPACE(sizeof(int) * nfds);
    skmsg.msg_control = alloca(skmsg.msg_controllen);
    assert(skmsg.msg_control);

    cmsg = CMSG_FIRSTHDR(&skmsg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int) * nfds);

    memcpy(CMSG_DATA(cmsg), fds, nfds * sizeof(fds[0]));
  }

  if ( info->cei_flags & CONTAINER_EXEC_ENABLE_WAIT )
    msg.sim_flags |= STK_RUN_FLAG_WAIT;

  msg.un.run.argc = argc;
  msg.un.run.envc = envc;

  memcpy(buf, &msg, sizeof(msg));

  out = buf + sizeof(msg);

  memcpy(out, info->cei_exec, strlen(info->cei_exec) + 1);
  out += strlen(info->cei_exec) + 1;

  for ( i = 0; info->cei_argv && info->cei_argv[i]; ++i ) {
    size_t sz = strlen(info->cei_argv[i]);
    memcpy(out, info->cei_argv[i], sz + 1);
    out += sz + 1;
  }

  for ( i = 0; info->cei_envv && info->cei_envv[i]; ++i ) {
    size_t sz = strlen(info->cei_envv[i]);
    memcpy(out, info->cei_envv[i], sz + 1);
    out += sz + 1;
  }

  if ( pthread_mutex_lock(&c->c_mutex) == 0 ) {
    pid_t ret;
    char wait_cbuf[CMSG_SPACE(sizeof(int))];

    iov.iov_base = buf;
    iov.iov_len = buf_size;

    err = sendmsg(c->c_init_comm, &skmsg, 0);
    if ( err < 0 ) {
      perror("container_execute: send");
      pthread_mutex_unlock(&c->c_mutex);
      return -1;
    }

    // Wait for pid
    skmsg.msg_flags = 0;
    skmsg.msg_name = NULL;
    skmsg.msg_namelen = 0;
    skmsg.msg_iov = &iov;
    skmsg.msg_iovlen = 1;
    iov.iov_base = &ret;
    iov.iov_len = sizeof(ret);

    if ( info->cei_flags & CONTAINER_EXEC_ENABLE_WAIT ) {
      skmsg.msg_control = wait_cbuf;
      skmsg.msg_controllen = CMSG_SPACE(sizeof(int));
    } else {
      skmsg.msg_control = NULL;
      skmsg.msg_controllen = 0;
    }

    err = recvmsg(c->c_init_comm, &skmsg, 0);
    if ( err < 0 ) {
      perror("container_execute: recv");
      pthread_mutex_unlock(&c->c_mutex);
      return -1;
    }

    if ( info->cei_flags & CONTAINER_EXEC_ENABLE_WAIT ) {
      struct cmsghdr *cmsg;
      cmsg = CMSG_FIRSTHDR(&skmsg);
      if ( !cmsg ||
           cmsg->cmsg_level != SOL_SOCKET ||
           cmsg->cmsg_type != SCM_RIGHTS ||
           cmsg->cmsg_len != CMSG_LEN(sizeof(int)) ) {
        fprintf(stderr, "container_execute: did not return wait fd\n");
        pthread_mutex_unlock(&c->c_mutex);
        return -1;
      }

      memcpy(&info->cei_wait_fd, CMSG_DATA(cmsg), sizeof(info->cei_wait_fd));
    } else {
      info->cei_wait_fd = -1;
    }

    pthread_mutex_unlock(&c->c_mutex);
    return ret;
  } else {
    fprintf(stderr, "container_execute: could not lock mutex\n");
    return -1;
  }
}

int container_kill(struct container *c, pid_t pid, int sig) {
  struct stkinitmsg msg;

  msg.sim_req = STK_REQ_KILL;
  msg.sim_flags = 0;
  msg.un.kill.which = pid;
  msg.un.kill.sig = sig;

  if ( pthread_mutex_lock(&c->c_mutex) == 0 ) {
    int ret = -1, err;

    if ( c->c_init_comm >= 0 ) {
      err = send(c->c_init_comm, &msg, sizeof(msg), 0);
      if ( err < 0 ) {
        perror("container_kill: send");
      } else {
        err = recv(c->c_init_comm, &ret, sizeof(ret), 0);
        if ( err < 0 ) {
          perror("container_kill: recv");
          ret = -errno;
        }
      }
    }

    pthread_mutex_unlock(&c->c_mutex);
    return ret;
  } else
    return -1;
}

static int containerpermfn(struct arpentry *ae, int op, void * arg, ssize_t argl) {
  struct container *c = STRUCT_FROM_BASE(struct container, c_arp_entry, ae);
  struct brpermrequest *perm;

  switch ( op ) {
  case ARP_ENTRY_CHECK_PERMISSION:
    perm = arg;
    perm->bpr_user_data = c;
    qdevtsub_init(&perm->bpr_start_event, OP_CONTAINER_CHECK_PERM, containerevtfn);
    eventloop_queue(perm->bpr_el, &perm->bpr_start_event);
    return 0;

  case ARP_ENTRY_DESCRIBE:
    return c->c_control(c, CONTAINER_CTL_DESCRIBE, arg, argl);

  default:
    fprintf(stderr, "containerpermfn: unknown op %d\n", op);
    return -2;
  }
}
