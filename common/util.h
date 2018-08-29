#ifndef __flock_util_H__
#define __flock_util_H__

#include <stddef.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/opensslconf.h>

#if !defined(OPENSSL_THREADS)
# error OpenSSL built without threads support
#endif

#ifndef HOST_NAME_MAX
# if defined(_POSIX_HOST_NAME_MAX)
#  define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
# elif defined(MAXHOSTNAMELEN)
#  define HOST_NAME_MAX MAXHOSTNAMELEN
# else
#  define HOST_NAME_MAX 64
# endif
#endif

#define KITE_PACKED __attribute__((packed))

#define KITE_APPLIANCE_NAME_MAX 256

#define SWAP(a, b)                                                      \
  if (1) {                                                              \
    typeof(a) x = a;                                                    \
    a = b;                                                              \
    b = x;                                                              \
  }
#define STRUCT_FROM_BASE(type, field, sub) ((type *) (((uintptr_t) sub) - offsetof(type, field)))

#define SOCKADDR_DATA(sa)                                       \
  ((sa)->sa_family == AF_INET ?                                 \
   ((void *) &((struct sockaddr_in *) sa)->sin_addr) :          \
   ((sa)->sa_family == AF_INET6 ?                               \
     ((void *) &((struct sockaddr_in6 *) sa)->sin6_addr) :      \
     (sa)->sa_data))                                            \

struct shared;
typedef void (*shfreefn)(const struct shared *);
struct shared {
  int sh_refcnt;
  shfreefn sh_free;
};

#define SHARED_INIT(shared, free)                               \
  if (1) {                                                      \
    (shared)->sh_refcnt = 1;                                    \
    (shared)->sh_free = (free);                                 \
  }
#define SHARED_REF(shared)  __sync_add_and_fetch(&(shared)->sh_refcnt, 1)
#define SHARED_UNREF(shared)                                    \
  if ( __sync_sub_and_fetch(&(shared)->sh_refcnt, 1) == 0 ) {   \
    (shared)->sh_free(shared);                                  \
  }

// Static bio
struct BIO_static {
  void *bs_buf;
  ssize_t bs_ptr, bs_sz;
};

#define BIO_STATIC_READ  1
#define BIO_STATIC_WRITE (-1)

void init_static_bio();
BIO *BIO_new_static(int mode, struct BIO_static *st);
void BIO_static_set(BIO *b, struct BIO_static *st);

#define BIO_STATIC_SIZE(s) labs((s)->bs_sz)
#define BIO_STATIC_OFS(s) ((s)->bs_ptr < 0 ? 0 : (s)->bs_ptr)
#define BIO_STATIC_CUR(s) ((s)->bs_buf + BIO_STATIC_OFS(s))

#define BIO_STATIC_IS_PEEKING(s) ((s)->bs_ptr < 0)

#define BIO_STATIC_IS_READ(s) ((s)->bs_sz > 0)
#define BIO_STATIC_IS_WRITE(s) ((s)->bs_sz < 0)

#define BIO_STATIC_WPENDING(s) (BIO_STATIC_IS_WRITE(s) ? (s)->bs_ptr : 0)
#define BIO_STATIC_RESET_WRITE(s) ((s)->bs_ptr = 0)
#define BIO_STATIC_SET_READ_SZ(s, sz) \
  if (1) {                            \
    (s)->bs_sz = (sz);                \
    (s)->bs_ptr = 0;                  \
  }

// File utilities
int mkdir_recursive(const char *path);
// Returns 0 if the src cannot fit in dst
int strncpy_safe(char *dst, const char *src, size_t sz);

int recv_fd(int fd, size_t num, int *fds);
int send_fd(int fd, size_t num, int *fds);

#endif
