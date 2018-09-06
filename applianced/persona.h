#ifndef __appliance_persona_H__
#define __appliance_persona_H__

#include <openssl/sha.h>
#include <uthash.h>

#include "buffer.h"
#include "util.h"

#define PERSONA_ID_X_LENGTH 64
#define PERSONA_ID_LENGTH   32

#define PAUTH_DATA_SIZE     256

#define PAUTH_TYPE_SHA256   1

struct pauth {
  int pa_type;
  struct pauth *pa_next;
  char pa_data[PAUTH_DATA_SIZE];
};

struct persona {
  struct shared p_shared;

  pthread_mutex_t p_mutex;

  char p_persona_id[PERSONA_ID_LENGTH];

  UT_hash_handle p_hh;

  // Personal information
  char *p_display_name;

  EVP_PKEY *p_private_key;

  // Authentication mechanisms that are required to log in
  struct pauth *p_auths;
};

#define PERSONA_REF(p) SHARED_REF(&(p)->p_shared)
#define PERSONA_UNREF(p) SHARED_UNREF(&(p)->p_shared)

int persona_init(struct persona *p,
                 const char *display_name,
                 int display_name_sz,
                 EVP_PKEY *private_key);
int persona_init_fp(struct persona *p, FILE *fp);
void persona_release(struct persona *p);

int persona_add_password(struct persona *p,
                         const char *password,
                         int password_sz);

// Save the persona to the FILE. You must hold p_mutex
int persona_save_fp(struct persona *p, FILE *fp);
struct persona *persona_read_fp(FILE *fp);

int persona_write_as_vcard(struct persona *p, struct buffer *b);

int persona_credential_validates(struct persona *p, const char *cred, size_t cred_sz);

// A personaset is a set of personas that have been serialized to a
// buffer. The buffer is managed via a shared pointer, so that its
// lifetime is managed separately from any personas.
//
// The serialization format is a sequence of VCards.
//
// A persona set has a unique sha256 key. The key of the newest
// persona set at the time of connection creation is transmitted in
// every start connection response. The current persona set is
// retrieved via call to appstate_get_personaset, which returns a
// reference to a new personaset. PERSONASET_UNREF should be called
// when complete.
//
// A persona set can be transmitted to a flock, but only a maximum
// number may be in transmission at any one time.
struct personaset {
  struct shared ps_shared;

  unsigned char ps_hash[SHA256_DIGEST_LENGTH];

  const char   *ps_buf;
  size_t        ps_buf_sz;
};

#define PERSONASET_REF(ps)   SHARED_REF(&(ps)->ps_shared)
#define PERSONASET_UNREF(ps) SHARED_UNREF(&(ps)->ps_shared)

struct personaset *personaset_from_buf(const char *buf, size_t sz);

#endif
