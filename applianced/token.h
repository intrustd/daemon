#ifndef __appliance_token_H__
#define __appliance_token_H__

#include <stdio.h>
#include <uthash.h>
#include <openssl/evp.h>

#include "persona.h"

#define TOKEN_LOGIN_PERM_URL "kite+perm://admin.flywithkite.com/login"

#define TOKEN_ID_LENGTH 32
#define SITE_ID_MAX_LENGTH 32

// A permission is a string. For memory purposes, these strings are
// interned, in this structure. Then, permissions can be compared via
// pointer comparison.
struct perm {
  struct shared perm_shared;

  UT_hash_handle perm_hh;

  const char perm_name[];
};

#define PERM_REF(perm) SHARED_REF(&(perm)->perm_shared)
#define PERM_UNREF(perm) SHARED_UNREF(&(perm)->perm_shared)
#define PERM_WREF(perm) SHARED_WREF(&(perm)->perm_shared)
#define PERM_WUNREF(perm) SHARED_WUNREF(&(perm)->perm_shared)

struct tokenperm {
  UT_hash_handle tp_hh;
  struct perm   *tp_perm;
};

// A token is a set of permissions, along with a description of who
// can use this permission.
struct token {
  struct shared tok_shared;

  UT_hash_handle tok_hh;

  const char tok_token_id[TOKEN_ID_LENGTH];

  uint32_t tok_flags;

  // Some tokens can only be used by a certain persona.
  const char tok_persona_id[PERSONA_ID_LENGTH];

  // Some tokens can only be used by certain sites.
  const EVP_MD *tok_site_digest;
  const char tok_site_id[SITE_ID_MAX_LENGTH];

  // Date of this token expiration
  time_t tok_expiration;

  // Finally, the hash table of permissions
  int tok_perm_count;
  struct tokenperm *tok_perms_hash, *tok_perms_list;

  int tok_app_count;
  const char **tok_apps;
};

#define TOKEN_FLAG_PERSONA_SPECIFIC 0x1
#define TOKEN_FLAG_SITE_SPECIFIC    0x2
#define TOKEN_FLAG_REQUIRES_LOGIN   0x4
#define TOKEN_FLAG_NEVER_EXPIRES    0x8
#define TOKEN_FLAG_TRANSFERABLE     0x10

#define TOKEN_REF(tok) SHARED_REF(&(tok)->tok_shared)
#define TOKEN_UNREF(tok) SHARED_UNREF(&(tok)->tok_shared)
#define TOKEN_WREF(tok) SHARED_WREF(&(tok)->tok_shared)
#define TOKEN_WUNREF(tok) SHARED_WUNREF(&(tok)->tok_shared)

// Gets a permission from the global permissions table. Returns a new
// reference, which ought to be freed via PERM_UNREF.
struct perm *perm_find_perm(const char *perm_name);
struct perm *perm_find_perm_ex(const char *perm_name, size_t perm_name_sz);

int perm_lock_all();
void perm_unlock_all();
struct perm *perm_find_perm_unlocked(const char *perm_name, size_t perm_name_sz);

// Create a new token
struct token *token_new_from_path(const char *path);
struct token *token_new_from_file(FILE *fl);

int token_check_permission(struct token *tok, const char *perm);
int token_check_permission_ex(struct token *tok, const char *perm, size_t perm_sz);

int token_verify_signature(FILE *fl, EVP_PKEY *pkey, const char *sign_hex, size_t hex_sz);

#endif
