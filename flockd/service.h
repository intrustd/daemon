#ifndef __flock_service_H__
#define __flock_service_H__

#include <pthread.h>
#include <openssl/ssl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "event.h"
#include "util.h"

#define PKT_BUF_SZ 2048

struct flocksvcclientstate;
struct flockservice {
  uint8_t fs_mutexes_initialized;

  pthread_mutex_t fs_service_mutex;   // Mutex for write operations on this socket
  struct flocksvcclientstate *fs_first_outgoing, *fs_last_outgoing;
  int fs_service_sk;
  struct fdsub fs_service_sub;
  struct BIO_static fs_sk_incoming;
  BIO_ADDR *fs_incoming_addr;

  pthread_rwlock_t fs_clients_mutex;  // Mutex for client hash table
  struct flocksvcclientstate *fs_clients_hash;

  SSL_CTX *fs_ssl_ctx;

  char fs_incoming_packet[PKT_BUF_SZ];
};

#define FS_SERVICE_MUTEX 0x1
#define FS_CLIENTS_MUTEX 0x2

int flockservice_init(struct flockservice *svc, X509 *cert, EVP_PKEY *pkey, struct eventloop *el, uint16_t port);
void flockservice_clear(struct flockservice *svc);
void flockservice_release(struct flockservice *svc);
void flockservice_start(struct flockservice *svc, struct eventloop *el);

void flock_service_fn(int op, void *arg);

#endif
