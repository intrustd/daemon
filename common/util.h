#ifndef __flock_util_H__
#define __flock_util_H__

#include <assert.h>
#include <byteswap.h>
#include <endian.h>
#include <stddef.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/opensslconf.h>

#if !defined(OPENSSL_THREADS)
# error OpenSSL built without threads support
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ntohll(x) (bswap_64(x))
#define htonll(x) (bswap_64(x))
#elif __BYTE_ORDER == __BIG_ENDIAN
#define ntohll(x) (x)
#define htonll(x) (x)
#else
# error Unknown endianness
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

#define SHFREE_NO_MORE_STRONG 2
#define SHFREE_NO_MORE_REFS   1

struct shared;
typedef void (*shfreefn)(const struct shared *, int level);
struct shared {
  uint64_t sh_refcnt;
  shfreefn sh_free;
};

#define strcmp_fixed(a, alen, b, blen) ((alen) < (blen) ? (-1) : ((alen) > (blen) ? 1 : strncmp((a), (b), ((alen) < (blen) ? (alen) : (blen)))))
#define static_strlen(s) (sizeof(s) - 1)

#define ADD_STRONG_REF(ref) (((ref) & 0xFFFFFFFF00000000) | (((ref) + 1) & 0xFFFFFFFF))
#define TRANSFER_REF(ref) ((((ref) - 0x100000000) & 0xFFFFFFFF00000000)| (((ref) + 1) & 0xFFFFFFFF))
#define SHARED_INIT(shared, free)                               \
  if (1) {                                                      \
    (shared)->sh_refcnt = 1;                                    \
    (shared)->sh_free = (free);                                 \
  }

static inline void shared_ref(struct shared *s) {
  uint64_t old_ref;

  do {
    old_ref = __sync_fetch_and_or(&s->sh_refcnt, 0);
    assert((old_ref & 0xFFFFFFFF) != 0); //if ( old_ref == 0 ) return -1;

  } while (!__sync_bool_compare_and_swap(&s->sh_refcnt, old_ref, ADD_STRONG_REF(old_ref)));
}

static inline void shared_wref(struct shared *s) {
  uint64_t old_ref;
  do {
    old_ref = __sync_fetch_and_or(&s->sh_refcnt, 0);
    assert(old_ref != 0);
  } while ( !__sync_bool_compare_and_swap(&s->sh_refcnt, old_ref, old_ref + 0x100000000) );
}

typedef struct {
  int sdf_level;
  struct shared *sdf_shared;
} SHARED_DEFERRED;

#define SHARED_WUNREF_DEFERRED(shared, d)                                \
  do {                                                                  \
    uint64_t __ref_ ## __LINE__ = __sync_sub_and_fetch(&(shared)->sh_refcnt, 0x100000000); \
    if ( __ref_ ## __LINE__ == 0 ) {                                    \
      (d)->sdf_level = SHFREE_NO_MORE_REFS;                             \
      (d)->sdf_shared = (shared);                                       \
    } else {                                                            \
      (d)->sdf_level = 0;                                               \
      (d)->sdf_shared = NULL;                                           \
    }                                                                   \
  } while (0);
#define SHARED_WUNREF(shared)                            \
  do {                                                   \
    SHARED_DEFERRED __def_ ## __LINE__;                  \
    SHARED_WUNREF_DEFERRED(shared, &__def_ ## __LINE__); \
    SHARED_DO_DEFERRED(&__def_ ## __LINE__);            \
  } while (0)

static inline int shared_lock(struct shared *s, SHARED_DEFERRED *d) {
  uint64_t old_ref;

  d->sdf_level = 0;
  d->sdf_shared = NULL;

  do {
    old_ref = __sync_fetch_and_or(&s->sh_refcnt, 0);
    if ( (old_ref & 0xFFFFFFFF) == 0 ) goto cleanup;

  } while ( !__sync_bool_compare_and_swap(&s->sh_refcnt, old_ref, TRANSFER_REF(old_ref)) );

  return 0;

 cleanup:
  // There are no more live references so free
  assert((old_ref & 0xFFFFFFFF00000000) != 0);
  SHARED_WUNREF_DEFERRED(s, d)
  return -1;
}

#define SHARED_DO_DEFERRED(d) if ( (d)->sdf_shared && (d)->sdf_level ) {  \
  (d)->sdf_shared->sh_free((d)->sdf_shared, (d)->sdf_level);          \
  }
#define SHARED_REF(shared)  shared_ref(shared)
#define SHARED_WREF(shared) shared_wref(shared)
#define SHARED_SAFE_LOCK(shared, defered) shared_lock(shared, defered)
static inline int shared_lock_imm(struct shared *s) {
  SHARED_DEFERRED d;
  int ret = SHARED_SAFE_LOCK(s, &d);
  SHARED_DO_DEFERRED(&d);
  return ret;
}
#define SHARED_LOCK(shared) shared_lock_imm(shared)
#define SHARED_UNREF(shared) do {                                       \
  uint64_t __ref_ ## __LINE__ =                                         \
    __sync_sub_and_fetch(&(shared)->sh_refcnt, 1);                      \
  if ( __ref_ ## __LINE__ == 0 ) {                                      \
    (shared)->sh_free(shared, SHFREE_NO_MORE_REFS);                     \
  } else if ( (__ref_ ## __LINE__ & 0xFFFFFFFF) == 0 ) {                \
    (shared)->sh_free(shared, SHFREE_NO_MORE_STRONG);                   \
  } } while (0)
#define SHARED_DEBUG(shared, str)                                       \
  do {                                                                  \
    uint64_t __cnt_ ## __LINE__ = __sync_fetch_and_or(&(shared)->sh_refcnt, 0); \
    fprintf(stderr, "SHARED_DEBUG: " str " (weak 0x%08lx, strong 0x%08lx)\n",     \
            (__cnt_ ## __LINE__ >> 32) & 0xFFFFFFFF, __cnt_ ## __LINE__ & 0xFFFFFFFF); \
  } while (0)

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

static inline int hex_value(char c) {
  if ( c >= '0' && c <= '9' ) return (c - '0');
  else if ( c >= 'A' && c <= 'F' ) return (c - 'A' + 10);
  else if ( c >= 'a' && c <= 'f' ) return (c - 'a' + 10);
  else return -1;
}

static inline int dec_value(char c) {
  if ( c >= '0' && c <= '9' )
    return (c - '0');
  return -1;
}

int parse_hex_str(const char *digest, unsigned char *out, int out_sz);
char *hex_digest_str(const unsigned char *digest, char *buf, int digest_sz);

// Doubly-linked lists

#define DLIST(type)                             \
  struct {                                      \
    type *dl_prev, *dl_next;                    \
  }
#define DLIST_HEAD(type)                        \
  struct {                                      \
    type *dh_first, *dh_last;                   \
  }

#define DLIST_INIT(head)                        \
  (head)->dh_first = (head)->dh_last = NULL;
#define DLIST_ENTRY_CLEAR(ent) (ent)->dl_prev = (ent)->dl_next = NULL
#define DLIST_EMPTY(head) (!(head)->dh_first && !(head)->dh_last)
#define DLIST_MOVE(dst, src)                    \
  do {                                          \
    (dst)->dh_first = (src)->dh_first;          \
    (dst)->dh_last = (src)->dh_last;            \
    (src)->dh_first = (src)->dh_last = NULL;    \
  } while (0)

#define DLIST_ITER(head, entry, v, tmp)                         \
  for ( (v) = (head)->dh_first, (tmp) = (v) ? (v)->entry.dl_next : NULL; (v); \
        (v) = (tmp), (tmp) = (v) ? (v)->entry.dl_next : NULL )

#define DLIST_CLEAR(head) (head)->dh_first = (head)->dh_last = NULL
#define DLIST_SET_FIRST(head, new_first)                         \
  do {                                                           \
    if ( (new_first) ) {                                         \
      (head)->dh_first = (new_first);                            \
    } else {                                                     \
      (head)->dh_first = (head)->dh_last = NULL;                 \
    }                                                            \
  } while (0)
#define DLIST_INSERT(head, dl, entry)                            \
  if ( (head)->dh_first ) {                                      \
    assert((head)->dh_last);                                     \
    (entry)->dl.dl_prev = (head)->dh_last;                       \
    (head)->dh_last->dl.dl_next = (entry);                       \
    (head)->dh_last = (entry);                                   \
  } else {                                                       \
    (head)->dh_first = (head)->dh_last = entry;                  \
  }
#define DLIST_REMOVE(head, dl, entry)                                \
  do {                                                               \
    if ( (head)->dh_first == (entry) ) {                             \
      (head)->dh_first = (entry)->dl.dl_next;                        \
      if ( !(head)->dh_first )                                       \
        (head)->dh_last = NULL;                                      \
      (entry)->dl.dl_prev = (entry)->dl.dl_next = NULL;              \
    } else if ( (head)->dh_last == (entry) ) {                       \
      (entry)->dl.dl_prev->dl.dl_next = NULL;                        \
      (head)->dh_last = (entry)->dl.dl_prev;                         \
      (entry)->dl.dl_prev = (entry)->dl.dl_next = NULL;              \
    } else {                                                         \
      entry->dl.dl_prev->dl.dl_next = entry->dl.dl_next;             \
      entry->dl.dl_next->dl.dl_prev = entry->dl.dl_prev;             \
      entry->dl.dl_prev = entry->dl.dl_next = NULL;                  \
    }                                                                \
  } while(0)
#define DLIST_ENTRY_IN_LIST(head, dl, entry)                    \
  ( ( (entry)->dl.dl_next && (entry)->dl.dl_prev ) ||           \
    ( (entry)->dl.dl_next && (entry) == (head)->dh_first ) ||   \
    ( (entry)->dl.dl_prev && (entry) == (head)->dh_last ) )

// Find the next newline in the buffer. Either '\n' or '\r\n' count as a newline, but not '\r'.
//
// If a newline is found *next_newline is set to the index of the
// first character of the newline, and *nl_length is set to the length
// of the newline sequence.
//
// Otherwise, *next_newline = -1 and *nl_length = 0
void find_newline(const char *buf, int buf_sz, int *next_newline, int *nl_length);

int b64_encode(const unsigned char *din, size_t din_sz,
               char *out, size_t *out_sz);

int uri_decode(const char *url, size_t url_sz,
               char *out, size_t out_sz);

int atoi_ex(char *s, char *e, int *out);

// Generates out_sz characters and places them in out. Each character
// chosen is human readable
//
// Returns 1 on success, 0 otherwise
int random_printable_string(char *out, size_t out_sz);

#endif
