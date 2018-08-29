#include <assert.h>
#include <unistd.h>
#include <memory.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "util.h"
#include "state.h"
#include "service.h"
#include "websocket.h"

void flockstate_clear(struct flockstate *st) {
  st->fs_flock_cert = NULL;
  st->fs_flock_privkey = NULL;
  st->fs_shards.fs_shard_count = 0;
  st->fs_shards.fs_our_shard_index = 0;
  st->fs_shards.fs_shards = NULL;
  st->fs_websocket_sk = 0;
  flockservice_clear(&st->fs_service);
  eventloop_clear(&st->fs_eventloop);
}

int flockstate_init(struct flockstate *st, struct flockconf *conf) {
  flockstate_clear(st);

  if ( flockstate_set_conf(st, conf) != 0 )
    return -1;

  return 0;
}

void flockstate_release(struct flockstate *st) {
  if ( st->fs_flock_cert )
    X509_free(st->fs_flock_cert);

  if ( st->fs_flock_privkey )
    EVP_PKEY_free(st->fs_flock_privkey);

  if ( st->fs_shards.fs_shards )
    free(st->fs_shards.fs_shards);

  eventloop_release(&st->fs_eventloop);

  flockservice_release(&st->fs_service);

  if ( st->fs_websocket_sk )
    close(st->fs_websocket_sk);

  flockstate_clear(st);
}

static int flockstate_set_shard_capacity(struct flockstate *st, int sz) {
  st->fs_shards.fs_shards = realloc(st->fs_shards.fs_shards, sz * sizeof(st->fs_shards.fs_shards[0]));
  if ( !st->fs_shards.fs_shards ) {
    fprintf(stderr, "Cannot increase shard capacity");
    return -1;
  }

  return 0;
}

static int flockstate_read_cert(struct flockstate *st, const char *cert_file) {
  FILE *fp;

  fp = fopen(cert_file, "rt");
  if ( !fp ) {
    perror("flockstate_read_cert");
    return -1;
  }

  st->fs_flock_cert = PEM_read_X509(fp, NULL, NULL, NULL);
  fclose(fp);

  if ( !st->fs_flock_cert ) {
    char err[256];
    ERR_error_string_n(ERR_get_error(), err, sizeof(err));
    fprintf(stderr, "flockstate_read_cert: invalid certificate: %s\n", err);
    return -1;
  }

  return 0;
}

static int flockstate_read_key(struct flockstate *st, const char *key_file) {
  FILE *fp;

  fp = fopen(key_file, "rt");
  if ( !fp ) {
    perror("flockstate_read_key");
    return -1;
  }

  st->fs_flock_privkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);

  if ( !st->fs_flock_privkey ) {
    char err[256];
    ERR_error_string_n(ERR_get_error(), err, sizeof(err));
    fprintf(stderr, "flockstate_read_key: invalid certificate: %s\n", err);
    return -1;
  }

  return 0;
}

static int flockstate_open_websocket(struct flockstate *st, uint16_t ws_port) {
  struct sockaddr_in ep;
  int err;

  err = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if ( err < 0 ) {
    perror("flockstate_open_websocket: socket");
    return -1;
  }

  st->fs_websocket_sk = err;
  fdsub_init(&st->fs_websocket_sub, &st->fs_eventloop, st->fs_websocket_sk,
             WS_EVENT_ACCEPT, websocket_fn);

  ep.sin_family = AF_INET;
  ep.sin_addr.s_addr = INADDR_ANY;
  ep.sin_port = htons(ws_port);

  err = bind(st->fs_websocket_sk, (struct sockaddr *) &ep, sizeof(ep));
  if ( err < 0 ) {
    perror("flockstate_open_websocket: bind");
    goto error;
  }

  err = listen(st->fs_websocket_sk, 10);
  if ( err < 0 ) {
    perror("flockstate_open_websocket: listen");
    goto error;
  }

  if ( set_socket_nonblocking(st->fs_websocket_sk) != 0 ) {
    fprintf(stderr, "Could not set websocket non-blocking\n");
    goto error;
  }

  return 0;

 error:
  close(st->fs_websocket_sk);
  st->fs_websocket_sk = 0;
  return -1;
}

static int flockstate_add_shard_by_hostname(struct flockstate *st, const char *hostname, uint16_t port) {
  char port_s[12];
  struct addrinfo hints, *addrs, *cur_addr;
  int err, this_shard_idx;

  assert(snprintf(port_s, sizeof(port_s), "%d", port) < sizeof(port_s));

  hints.ai_flags = AI_NUMERICSERV;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;

  err = getaddrinfo(hostname, port_s, &hints, &addrs);
  if ( err != 0 ) return -1;

  this_shard_idx = st->fs_shards.fs_shard_count++;

  // Scan the host entries and use the first IPv4
  for ( cur_addr = addrs; cur_addr; cur_addr = cur_addr->ai_next ) {
    if ( cur_addr->ai_family == AF_INET ) {
      assert(cur_addr->ai_addrlen == sizeof(st->fs_shards.fs_shards[this_shard_idx]));
      memcpy(&st->fs_shards.fs_shards[this_shard_idx], cur_addr->ai_addr, sizeof(st->fs_shards.fs_shards[this_shard_idx]));
    }
  }

  freeaddrinfo(addrs);
  return 0;
}

static int flockstate_open_shards(struct flockstate *st, const char *shards_file, uint16_t port) {
  return -1; // TODO
}

static int flockstate_only_shard(struct flockstate *st, uint16_t port) {
  char hostname[HOST_NAME_MAX];

  if ( flockstate_set_shard_capacity(st, 1) != 0 )
    return -1;

  st->fs_shards.fs_our_shard_index = 0;

  if ( gethostname(hostname, sizeof(hostname)) < 0 ) {
    perror("gethostname");
    return -1;
  }

  // Assumes there is enough space in fs_shards
  if ( flockstate_add_shard_by_hostname(st, hostname, port) != 0 )
    return -1;

  return 0;
}

int flockstate_set_conf(struct flockstate *st, struct flockconf *conf) {
  int err;

  flockstate_release(st);

  err = eventloop_init(&st->fs_eventloop);
  if ( err != 0 ) {
    fprintf(stderr, "eventloop_init: %s\n", strerror(err));
    goto error;
  }

  if ( flockstate_read_cert(st, conf->fc_certificate_file) != 0 ) {
    fprintf(stderr, "Could not read flock certificate\n");
    goto error;
  }

  if ( flockstate_read_key(st, conf->fc_privkey_file) != 0 ) {
    fprintf(stderr, "Could not read flock private key\n");
    goto error;
  }

  if ( flockservice_init(&st->fs_service, st->fs_flock_cert, st->fs_flock_privkey,
                         &st->fs_eventloop, conf->fc_service_port) != 0 ) {
    fprintf(stderr, "Could not open service socket\n");
    goto error;
  }

  if ( flockstate_open_websocket(st, conf->fc_websocket_port) != 0 ) {
    fprintf(stderr, "Could not open websocket\n");
    goto error;
  }

  if ( conf->fc_shards_file ) {
    if ( flockstate_open_shards(st, conf->fc_shards_file, conf->fc_service_port) != 0 ) goto error;
  } else {
    if ( flockstate_only_shard(st, conf->fc_service_port) != 0 ) goto error;
  }

  return 0;

 error:
  flockstate_release(st);
  return -1;
}

void flockstate_start_services(struct flockstate *st) {
  flockservice_start(&st->fs_service, &st->fs_eventloop);

  st->fs_websocket_sub.fds_subscriptions |= FD_SUB_READ;;
  eventloop_subscribe_fd(&st->fs_eventloop, st->fs_websocket_sk, &st->fs_websocket_sub);
}
