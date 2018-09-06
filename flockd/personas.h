#ifndef __flocks_personas_H__
#define __flocks_personas_H__

#include <openssl/sha.h>
#include <string.h>

#include "util.h"
#include "buffer.h"
#include "event.h"

// Can be used to write out a cpersonaset from a personasfetcher
struct personaswriter {
  struct cpersonaset *pw_cps;
  uint32_t pw_offset;
};

#define PERSONASWRITER_IS_VALID(pw) ((pw)->pw_cps != NULL)
#define personaswriter_size(pw) (cps_size((pw)->pw_cps))
int personaswriter_get_chunk(struct personaswriter *pw, char *out, int out_sz);
void personaswriter_release(struct personaswriter *pw);

// Arg is pointer to struct iovec
#define CPERSONASET_WRITE  1
// Return value is offset, or -1 on error, -2 on not implemented
#define CPERSONASET_TELL   2
// Complete for read
#define CPERSONASET_RCOMPLETE 3
#define CPERSONASET_GET_READER 4
#define CPERSONASET_READ 5
#define CPERSONASET_GET_SIZE 6

struct cpsreadargs {
  char *cpsra_buf;
  int cpsra_sz;
  int cpsra_offs;
};

#define cps_size(cps) ((cps)->cps_fn((cps), CPERSONASET_GET_SIZE, NULL))
#define cps_tell(cps) ((cps)->cps_fn((cps), CPERSONASET_TELL, NULL))
#define cps_write(cps, iov) ((cps)->cps_fn((cps), CPERSONASET_WRITE, iov))
#define cps_rcomplete(cps) ((cps)->cps_fn((cps), CPERSONASET_RCOMPLETE, NULL))
#define cps_get_reader(cps, rp) ((cps)->cps_fn((cps), CPERSONASET_GET_READER, rp))
#define cps_read(cps, rp) ((cps)->cps_fn((cps), CPERSONASET_READ, rp))

struct cpersonaset;
typedef int(*cpersonasetfn)(struct cpersonaset *, int, void *);

// A cached persona set
struct cpersonaset {
  struct shared    cps_shared;
  cpersonasetfn    cps_fn;
};

void cpersonaset_init(struct cpersonaset *cps, cpersonasetfn ctl, shfreefn do_free);


#define CPERSONASET_REF(cps) SHARED_REF(&(cps)->cps_shared)
#define CPERSONASET_UNREF(cps) SHARED_UNREF(&(cps)->cps_shared)

// A cached persona set that is stored completely in memory
struct cmempersonaset {
  struct cpersonaset cmps_cached;
  struct buffer      cmps_buffer;
};

struct cmempersonaset *cmempersonaset_alloc();

// Returns 0 to skip, 1 if processed
#define PF_OP_AIPF_RECEIVE_STUN 1

struct personasfetcher;

// Returns -2 on not implemented
typedef int(*personasfetcherfn)(struct personasfetcher *, int, void *arg);

struct personasfetcher {
  struct shared     pf_shared;

  pthread_mutex_t   pf_mutex;

  unsigned char     pf_hash[SHA256_DIGEST_LENGTH];

  // No need to hold pf_mutex
  personasfetcherfn pf_control;

  // Callbacks to be called when the fetch is complete
  evtqueue          pf_completion;

  // 0 if the fetch is in progress, -1 on error, 1 if the fetch is
  // complete
  int               pf_is_complete;

  // Where we are writing the cache entry
  struct cpersonaset *pf_cached;
};

#define PERSONASFETCHER_REF(pf) SHARED_REF(&(pf)->pf_shared)
#define PERSONASFETCHER_UNREF(pf) SHARED_UNREF(&(pf)->pf_shared)
#define PERSONASFETCHER_WREF(pf) SHARED_WREF(&(pf)->pf_shared)
#define PERSONASFETCHER_WUNREF(pf) SHARED_WUNREF(&(pf)->pf_shared)
#define PERSONASFETCHER_LOCK(pf) SHARED_LOCK(&(pf)->pf_shared)

int personasfetcher_init(struct personasfetcher *pf,
                         const unsigned char *personaset_hash,
                         struct cpersonaset *cache_entry,
                         personasfetcherfn fn,
                         shfreefn do_free);
struct personasfetcher *personasfetcher_new_from_cached(const unsigned char *hash,
                                                        struct cpersonaset *cache_entry,
                                                        struct eventloop *el);
void personasfetcher_release(struct personasfetcher *pf);
// Make sure the event keeps a reference to the personasfetcher
void personasfetcher_request_event(struct personasfetcher *pf, struct eventloop *el,
                                   struct qdevtsub *evt);

// Sets the completion status and trigger all waiters, if the personasfetcher has not ended
void personasfetcher_mark_complete(struct personasfetcher *pf, struct eventloop *el, int sts);

#define personasfetcher_hash_matches(pf, hash) (memcmp((pf)->pf_hash, hash, sizeof((pf)->pf_hash)) == 0)

int personasfetcher_init_personaswriter(struct personasfetcher *pf,
                                        struct personaswriter *w);
#endif
