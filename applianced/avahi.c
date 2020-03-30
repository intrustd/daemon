#include "avahi.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int is_local_address(char *addr, size_t addr_sz) {
  static const char local_suffix[] = { '.', 'l', 'o', 'c', 'a', 'l' };
  int addr_len = strnlen(addr, addr_sz);

  if ( addr_len < 0 ) return 0;

  if ( addr[addr_len - 1] == '.' )
    addr_len --;

  if ( addr_len < sizeof(local_suffix) )
    return 0;

  if ( memcmp(addr + (addr_len - sizeof(local_suffix)), local_suffix, sizeof(local_suffix)) == 0 )
    return 1;
  else
    return 0;
}

#define OP_AVAHI_STARTS EVT_CTL_CUSTOM
#define OP_AVAHI_READ_AVAILABLE (EVT_CTL_CUSTOM + 1)
#define OP_AVAHI_TIMEOUT (EVT_CTL_CUSTOM + 2)

#define AVAHI_SOCKET_TIMEOUT 10000 // Timeout after ten seconds

#define AVAHI_PARSE_RESPONSE_NOT_FOUND 404

#define AVAHI_RESPONSE_TIMEOUT_REACHED 15

static void avahi_signal_finish(struct avahirequest *ar, int sts);
static int avahi_start_resolve(struct avahirequest *ar, int what);
static void avahi_close_socket(struct avahirequest *ar);
static void avahi_unset_timeout(struct avahirequest *ar);
static void avahi_set_timeout(struct avahirequest *ar);
static void avahi_shutdown(const struct shared *s, int level);
static void avahi_subscribe_fd(struct avahirequest *ar);

static void avahi_resolve_next(struct avahirequest *ar, int sts_on_done) {
  if ( ar->ar_status == AVAHI_RESOLVE_IPV6 ) {
    avahi_start_resolve(ar, AVAHI_RESOLVE_IPV4);
  } else {
    avahi_close_socket(ar);
    avahi_signal_finish(ar, sts_on_done);
  }
}

static int avahi_parse_response(struct avahirequest *ar) {
  char *first_newline = memchr(ar->ar_response, '\n', ar->ar_response_len);
  if ( first_newline ) {
    int response_len = first_newline - ar->ar_response;
    if ( response_len == 0 )
      return -1;

    *first_newline = '\0';

    if ( ar->ar_response[0] == '+' ) {
      int field0, field1; // TODO what are these fields?
      char domain[257];
      char addr[257];

      int num_items;
      socklen_t addr_sz = sizeof(ar->ar_resolved_addr);

      num_items = sscanf(ar->ar_response + 1, "%d %d %257s %257s", &field0, &field1, domain, addr);
      if ( num_items != 4 ) {
        fprintf(stderr, "avahi_parse_response: could not read all fields (read %d fields, expected 4)\n", num_items);
        return -1;
      }

      parse_address(addr, sizeof(addr), ar->ar_port,
                    &ar->ar_resolved_addr.sa, &addr_sz);

      return 0;
    } else if ( ar->ar_response[0] == '-' ) {
      char avahi_status_str[257];
      int avahi_status;
      int num_items;

      memset(avahi_status_str, 0, sizeof(avahi_status));

      num_items = sscanf(ar->ar_response + 1, "%d %257s", &avahi_status, avahi_status_str);
      if ( num_items == 0 ) {
        fprintf(stderr, "avahi_parse_response: invaid response: %s\n", ar->ar_response);
        return -1;
      }

      if ( num_items > 0 && avahi_status == AVAHI_RESPONSE_TIMEOUT_REACHED ) {
        return AVAHI_PARSE_RESPONSE_NOT_FOUND;
      } else if ( num_items == 2 )
        fprintf(stderr, "avahi_parse_response: got avahi status %s (Code is %d)\n",
                avahi_status_str, avahi_status);

      return -1;
    } else {
      fprintf(stderr, "avahi_parse_response: first character of response should indicate success or error\n");
      fprintf(stderr, "avahi_parse_response: instead got %s\n", ar->ar_response);

      return -1;
    }
  } else
    return 1; // Keep going
}

static void avahi_service_read(struct avahirequest *ar) {
  int bytes_read, bytes_left = sizeof(ar->ar_response) - ar->ar_response_len;

  bytes_read = recv(ar->ar_fd, ar->ar_response + ar->ar_response_len, bytes_left, 0);
  if ( bytes_read < 0 && errno != EAGAIN ) {
    perror("avahi_service_read: recv");
    avahi_signal_finish(ar, AVAHI_UNAVAILABLE);
  } else if ( bytes_read > 0 ) {
    int err;
    ar->ar_response_len += bytes_read;

    err = avahi_parse_response(ar);
    if ( err < 0 ) {
      fprintf(stderr, "avahi_service_read: invalid response received\n");
      avahi_signal_finish(ar, AVAHI_INVALID_RESPONSE);
    } else if ( err == AVAHI_PARSE_RESPONSE_NOT_FOUND ) {
      avahi_resolve_next(ar, AVAHI_NOT_FOUND);
    } else if ( err > 0 ) {
      // Needs more data

      if ( ar->ar_response_len >= sizeof(ar->ar_response) ) {
        fprintf(stderr, "avahi_service_read: response overflow\n");
        avahi_signal_finish(ar, AVAHI_RESPONSE_OVERFLOW);
      } else {
        avahi_subscribe_fd(ar);
      }
    } else if ( err == 0 ) {
      // If we succeeded, one address would have been placed in the given ice candidate
      avahi_signal_finish(ar, AVAHI_SUCCESS);
    }
  } else if ( errno == EAGAIN ) {
    avahi_subscribe_fd(ar);
  }
}

static void avahi_service_error(struct avahirequest *ar) {
  int err;
  socklen_t errlen = sizeof(err);

  if ( getsockopt(ar->ar_fd, SOL_SOCKET, SO_ERROR, (void *)&err, &errlen) == 0 ) {
    fprintf(stderr, "avahi_service_error: got socket error: %s\n", strerror(err));
  } else
    perror("avahi_service_error: getsockopt(SOL_SOCKET, SO_ERROR)");

  avahi_resolve_next(ar, AVAHI_UNAVAILABLE);
}

static void avahirequest_fn(struct eventloop *el, int op, void *arg) {
  struct qdevent *evt = (struct qdevent *) arg;
  struct fdevent *fde = (struct fdevent *) arg;
  struct avahirequest *ar;

  switch ( op ) {
  case OP_AVAHI_STARTS:
    ar = STRUCT_FROM_BASE(struct avahirequest, ar_start_evt, evt->qde_sub);
    if ( AVAHIREQUEST_LOCK(ar) == 0 ) {
      SAFE_MUTEX_LOCK(&ar->ar_mutex);
      avahi_start_resolve(ar, AVAHI_RESOLVE_IPV6);
      // Keep the reference. This will either be used to complete the
      // request, or if the above function errored, then the finish
      // event
      pthread_mutex_unlock(&ar->ar_mutex);
    }
    break;
  case OP_AVAHI_READ_AVAILABLE:
    ar = STRUCT_FROM_BASE(struct avahirequest, ar_sock_evt, fde->fde_sub);

    if ( FD_READ_PENDING(fde) && AVAHIREQUEST_LOCK(ar) == 0 ) {
      // The weak reference from the subscribe
      avahi_service_read(ar);
      AVAHIREQUEST_UNREF(ar);
    }

    if ( FD_ERROR_PENDING(fde) && AVAHIREQUEST_LOCK(ar) == 0 ) {
      avahi_service_error(ar);
      AVAHIREQUEST_UNREF(ar);
    }
    break;
  case OP_AVAHI_TIMEOUT:
    ar = STRUCT_FROM_BASE(struct avahirequest, ar_timeout_evt, evt->qde_sub);
    if ( AVAHIREQUEST_LOCK(ar) == 0 ) {
      SAFE_MUTEX_LOCK(&ar->ar_mutex);
      avahi_close_socket(ar);
      avahi_signal_finish(ar, AVAHI_NOT_RESPONDING);
      pthread_mutex_unlock(&ar->ar_mutex);
      AVAHIREQUEST_UNREF(ar);
    }
    break;
  default:
    fprintf(stderr, "avahirequest_fn: Unknown op %d\n", op);
  }
}

static void avahi_subscribe_fd(struct avahirequest *ar) {
  int new_subs;

  AVAHIREQUEST_WREF(ar); // For read event
  AVAHIREQUEST_WREF(ar); // For error event

  new_subs = eventloop_subscribe_fd(ar->ar_eventloop, ar->ar_fd,
                                    FD_SUB_READ | FD_SUB_ERROR, &ar->ar_sock_evt);

  if ( (new_subs & FD_SUB_READ) == 0 )
    AVAHIREQUEST_WUNREF(ar);

  if ( (new_subs & FD_SUB_ERROR) == 0 )
    AVAHIREQUEST_WUNREF(ar);
}

static void avahi_signal_finish(struct avahirequest *ar, int sts) {
  if ( ar->ar_status > 0 ) {
    ar->ar_status = sts;
    avahi_unset_timeout(ar);
    eventloop_queue(ar->ar_eventloop, &ar->ar_finished_evt);
  }
}

static void avahi_close_socket(struct avahirequest *ar) {
  int old_subs;

  if ( ar->ar_fd < 0 )
    return;

  old_subs = eventloop_unsubscribe_fd(ar->ar_eventloop, ar->ar_fd,
                                      FD_SUB_ALL, &ar->ar_sock_evt);

  if ( old_subs & FD_SUB_READ )
    AVAHIREQUEST_WUNREF(ar);
  if ( old_subs & FD_SUB_ERROR )
    AVAHIREQUEST_WUNREF(ar);

  close(ar->ar_fd);
  ar->ar_fd = -1;
}

static int open_avahi_socket() {
  char *avahi_socket = getenv("AVAHI_SOCKET");
  int fd;
  struct sockaddr_un sa;

  if ( !avahi_socket )
    avahi_socket = "/run/avahi-daemon/socket";

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if ( fd < 0 ) {
    perror("avahi_socket: socket(AF_UNIX, SOCK_STREAM, 0)");
    return -1;
  }

  /* Make sure this file description is closed on exec */
  if ( fcntl(fd, F_SETFD, FD_CLOEXEC) < 0 ) {
    perror("open_avahi_socket: fcntl(fd, F_SETFD, FD_CLOEXEC)");
    close(fd);
    return -1;
  }

  memset(&sa, 0, sizeof(sa));
  sa.sun_family = AF_UNIX;
  strncpy(sa.sun_path, avahi_socket, sizeof(sa.sun_path) - 1);

  if ( connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 ) {
    perror("avahi_socket: connect");
    close(fd);
    return -1;
  }

  return fd;
}

static int send_avahi_request(int fd, const char *family, const char *domain) {
  char avahi_request[DNS_DOMAIN_MAXLEN + 256];
  int err, request_sz;

  err = request_sz =
    snprintf(avahi_request, sizeof(avahi_request), "RESOLVE-HOSTNAME-%s %s\n", family, domain);
  if ( err >= sizeof(avahi_request) ) {
    fprintf(stderr, "send_avahi_request: request overflow\n");
    return -1;
  }

  fprintf(stderr, "Send avahi request %s\n", avahi_request);

  err = send(fd, avahi_request, request_sz, 0);
  if ( err < 0 ) {
    perror("send_avahi_request: send");
    return -1;
  } else if ( err < request_sz ) {
    fprintf(stderr, "send_avahi_request: could not send entire avahi request\n");
    return -1;
  } else
    return 0;
}

static const char *avahi_family(int sts) {
  if ( sts == AVAHI_RESOLVE_IPV6 )
    return "IPV6";
  else if ( sts == AVAHI_RESOLVE_IPV4 )
    return "IPV4";
  else
    return "UNKNOWN";
}

static int avahi_start_resolve(struct avahirequest *ar, int what) {
  int err;

  ar->ar_status = what;
  ar->ar_response_len = 0;

  avahi_close_socket(ar);
  avahi_unset_timeout(ar);

  ar->ar_fd = open_avahi_socket();
  if ( ar->ar_fd == -1 ) {
    fprintf(stderr, "avahi_start_resolve: could not open avahi socket\n");
    avahi_signal_finish(ar, AVAHI_UNAVAILABLE);
    return -1;
  }

  err = send_avahi_request(ar->ar_fd, avahi_family(what), ar->ar_domain);
  if ( err < 0 ) {
    close(ar->ar_fd);
    ar->ar_fd = -1;
    fprintf(stderr, "avahi_start_resolve: could not send avahi request\n");
    avahi_signal_finish(ar, AVAHI_UNAVAILABLE);
    return -1;
  }

  // Now make the socket non blocking
  if ( set_socket_nonblocking(ar->ar_fd) < 0 ) {
    perror("avahi_start_resolve: set_socket_nonblocking");
    close(ar->ar_fd);
    ar->ar_fd = -1;
    avahi_signal_finish(ar, AVAHI_UNAVAILABLE);
    return -1;
  }

  fdsub_init(&ar->ar_sock_evt, ar->ar_eventloop,
             ar->ar_fd, OP_AVAHI_READ_AVAILABLE, avahirequest_fn);
  avahi_subscribe_fd(ar);
  avahi_set_timeout(ar);

  return 0;
}

struct avahirequest *avahirequest_alloc(const char *domain, size_t domain_sz, uint16_t port,
                                        size_t data_sz, int finish_op, evtctlfn finish_fn) {
  int domain_len = strnlen(domain, domain_sz);
  struct avahirequest *ar = (struct avahirequest *) malloc(sizeof(struct avahirequest) + data_sz);
  if ( !ar )
    return NULL;

  SHARED_INIT(&ar->ar_shared, avahi_shutdown);

  if ( domain_len >= sizeof(ar->ar_domain) ) {
    free(ar);
    return NULL;
  }

  if ( pthread_mutex_init(&ar->ar_mutex, NULL) != 0 ) {
    free(ar);
    return NULL;
  }

  memset(ar->ar_domain, 0, sizeof(ar->ar_domain));
  strncpy(ar->ar_domain, domain, sizeof(ar->ar_domain) - 1);

  qdevtsub_init(&ar->ar_finished_evt, finish_op, finish_fn);
  qdevtsub_init(&ar->ar_start_evt, OP_AVAHI_STARTS, avahirequest_fn);

  ar->ar_status = AVAHI_UNSTARTED;
  ar->ar_fd = -1;
  ar->ar_eventloop = NULL;
  INTRUSTD_SOCK_ADDR_INIT(&ar->ar_resolved_addr);
  ar->ar_port = port;

  return ar;
}

static void avahi_set_timeout(struct avahirequest *ar) {
  AVAHIREQUEST_WREF(ar);
  timersub_init_from_now(&ar->ar_timeout_evt, AVAHI_SOCKET_TIMEOUT,
                         OP_AVAHI_TIMEOUT, avahirequest_fn);

  eventloop_subscribe_timer(ar->ar_eventloop, &ar->ar_timeout_evt);
}

static void avahi_unset_timeout(struct avahirequest *ar) {
  if ( eventloop_cancel_timer(ar->ar_eventloop, &ar->ar_timeout_evt) )
    AVAHIREQUEST_WUNREF(ar);
}

void avahirequest_start(struct avahirequest *ar, struct eventloop *el) {
  ar->ar_status = AVAHI_IN_PROGRESS;
  ar->ar_eventloop = el;
  AVAHIREQUEST_WREF(ar);
  eventloop_queue(el, &ar->ar_start_evt);
}

static void avahi_shutdown(const struct shared *sh, int level) {
  struct avahirequest *ar = (struct avahirequest *)sh;
  if ( level == SHFREE_NO_MORE_STRONG ) {
    SAFE_MUTEX_LOCK(&ar->ar_mutex);
    avahi_close_socket(ar);
    avahi_unset_timeout(ar);
    pthread_mutex_unlock(&ar->ar_mutex);
  } else if ( level == SHFREE_NO_MORE_REFS ) {
    fprintf(stderr, "Free avahi request %s\n", ar->ar_domain);

    avahi_close_socket(ar);

    pthread_mutex_destroy(&ar->ar_mutex);

    free(ar);
  }
}

int avahirequest_get_status(struct avahirequest *ar, int *sts, intrustd_sock_addr *addr) {
  if ( pthread_mutex_lock(&ar->ar_mutex) == 0 ) {
    *sts = ar->ar_status;
    if ( addr ) {
      INTRUSTD_SOCK_ADDR_INIT(addr);
      if ( ar->ar_status == AVAHI_SUCCESS )
        memcpy(addr, &ar->ar_resolved_addr, sizeof(*addr));
    }
    pthread_mutex_unlock(&ar->ar_mutex);
    return 0;
  } else
    return -1;
}

const char *avahi_error_string(int sts) {
  switch (sts) {
  case AVAHI_SUCCESS:
    return "Success";
  case AVAHI_UNAVAILABLE:
    return "Avahi unavailable";
  case AVAHI_NOT_RESPONDING:
    return "Avahi daemon not responding";
  case AVAHI_INVALID_RESPONSE:
    return "Malformed response from Avahi";
  case AVAHI_RESPONSE_OVERFLOW:
    return "Avahi response too long";
  case AVAHI_NOT_FOUND:
    return "Local domain not found";
  default:
    return "Avahi name resolution in progress";
  }
}
