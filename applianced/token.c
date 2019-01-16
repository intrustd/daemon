#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include "jsmn.h"
#include "token.h"

static pthread_mutex_t g_perms_mutex = PTHREAD_MUTEX_INITIALIZER;
struct perm * g_perms = NULL;

#define TM_YEAR_EPOCH 1900
#define TOKEN_MIN_SECRET_LENGTH 128

static void permfreefn(const struct shared *sh, int lvl) {
  struct perm *p = STRUCT_FROM_BASE(struct perm, perm_shared, sh);

  if ( lvl == SHFREE_NO_MORE_STRONG ) {
    if ( pthread_mutex_lock(&g_perms_mutex) == 0 ) {
      struct perm *existing;
      HASH_FIND(perm_hh, g_perms, p->perm_name, strlen(p->perm_name), existing);
      if ( existing == p ) {
        HASH_DELETE(perm_hh, g_perms, existing);
      }
      pthread_mutex_unlock(&g_perms_mutex);

      if ( existing )
        PERM_WUNREF(existing);
    }
  } else {
    free(p);
  }
}

int perm_lock_all() {
  return pthread_mutex_lock(&g_perms_mutex);
}

void perm_unlock_all() {
  pthread_mutex_unlock(&g_perms_mutex);
}

struct perm *perm_find_perm(const char *perm_name) {
  return perm_find_perm_ex(perm_name, strlen(perm_name));
}

struct perm *perm_find_perm_ex(const char *perm_name, size_t perm_name_sz) {
  if ( perm_lock_all() == 0 ) {
    struct perm *ret = perm_find_perm_unlocked(perm_name, perm_name_sz);
    perm_unlock_all();
    return ret;
  } else
    return NULL;
}

struct perm *perm_find_perm_unlocked(const char *perm_name, size_t perm_name_sz) {
  struct perm *ret;

  HASH_FIND(perm_hh, g_perms, perm_name, perm_name_sz, ret);
  if ( ret ) {
    PERM_REF(ret);
  } else {
    ret = malloc(sizeof(*ret) + perm_name_sz + 1);
    if ( ret ) {
      char *new_perm_name = (char *) ret->perm_name;
      SHARED_INIT(&ret->perm_shared, permfreefn);
      memcpy(new_perm_name, perm_name, perm_name_sz);
      new_perm_name[perm_name_sz] = '\0';
      HASH_ADD(perm_hh, g_perms, perm_name, perm_name_sz, ret);
      PERM_WREF(ret);
    }
  }
  return ret;
}

// Token

static void tokfreefn(const struct shared *tok_sh, int level) {
  struct token *tok = STRUCT_FROM_BASE(struct token, tok_shared, tok_sh);

  if ( level == SHFREE_NO_MORE_REFS ) {
    int i;
    struct tokenperm *cur_perm, *tmp_perm;

    HASH_ITER(tp_hh, tok->tok_perms_hash, cur_perm, tmp_perm) {
      HASH_DELETE(tp_hh, tok->tok_perms_hash, cur_perm);
      PERM_UNREF(cur_perm->tp_perm);
    }
    free(tok->tok_perms_list);

    for ( i = 0; i < tok->tok_app_count; ++i ) {
      free((void *) tok->tok_apps[i]);
    }

    if ( tok->tok_apps )
      free(tok->tok_apps);
    free(tok);
  }
}

struct token *token_new_from_path(const char *path) {
  struct token *ret;
  FILE *fl = fopen(path, "rb");
  if ( !fl ) {
    perror("token_new_from_path: fopen");
    return NULL;
  }

  ret = token_new_from_file(fl);

  fclose(fl);

  return ret;
}

struct token *token_new_from_file(FILE *fl) {
  struct token *new_token = NULL;
  jsmntok_t *tokens = NULL;
  struct buffer b;
  const char *buf;
  size_t buf_sz;
  jsmn_parser p;
  int ret, i, token_count = 16, app_count = 0, perm_count = 0, has_secret = 0;

  struct tm expiration;
  char microsecs[7] = { 0 };

  enum {
    TOKEN_STATE_START,
    TOKEN_STATE_MAIN_OBJECT_KEY,
    TOKEN_STATE_MAIN_OBJECT_PERMISSIONS,
    TOKEN_STATE_MAIN_OBJECT_APPLICATIONS,
    TOKEN_STATE_MAIN_OBJECT_LOGIN_REQUIRED,
    TOKEN_STATE_MAIN_OBJECT_PERSONA,
    TOKEN_STATE_MAIN_OBJECT_SITE,
    TOKEN_STATE_MAIN_OBJECT_EXPIRATION,
    TOKEN_STATE_MAIN_OBJECT_SECRET,
    TOKEN_STATE_MAIN_OBJECT_IN_PERMISSIONS,
    TOKEN_STATE_MAIN_OBJECT_IN_APPLICATIONS
  } state = TOKEN_STATE_START;

  memset(&expiration, 0, sizeof(expiration));
  buffer_init(&b);

  if ( buffer_read_from_file_ex(&b, fl) != 0 ) {
    buffer_finalize(&b, &buf, &buf_sz);
    free((void *)buf);
    return NULL;
  }


  jsmn_init(&p);
  buffer_finalize(&b, &buf, &buf_sz);

  do {
    jsmntok_t *new_tokens;

    new_tokens = realloc(tokens, sizeof(*tokens) * token_count);
    if ( !new_tokens ) {
      fprintf(stderr, "token_new_from_file: not enough space for token");
      free((void *)buf);
      return NULL;
    }
    tokens = new_tokens;

    ret = jsmn_parse(&p, buf, buf_sz, tokens, token_count);

    if ( ret == JSMN_ERROR_PART ) {
      free((void *)buf);
      free(tokens);
      fprintf(stderr, "token_new_from_file: JSON ended prematurely\n");
      return NULL;
    } else if ( ret == JSMN_ERROR_INVAL ) {
      free((void *)buf);
      free(tokens);
      fprintf(stderr, "token_new_from_file: invalid JSON in token\n");
      return NULL;
    } else if ( ret == JSMN_ERROR_NOMEM ) {
      token_count *= 2;
      continue;
    }
  } while ( ret == JSMN_ERROR_NOMEM );

  new_token = malloc(sizeof(*new_token));
  if ( !new_token ) {
    fprintf(stderr, "token_new_from_file: could not allocate new token\n");
    goto error;
  }

  SHARED_INIT(&new_token->tok_shared, tokfreefn);
  SHA256((const unsigned char *)buf, buf_sz, (unsigned char *) new_token->tok_token_id);
  new_token->tok_flags = TOKEN_FLAG_NEVER_EXPIRES;
  memset((unsigned char *)new_token->tok_persona_id, 0, PERSONA_ID_LENGTH);
  memset((unsigned char *)new_token->tok_site_id, 0, SITE_ID_MAX_LENGTH);
  new_token->tok_expiration = 0;
  new_token->tok_perm_count = 0;
  new_token->tok_perms_list = NULL;
  new_token->tok_perms_hash = NULL;
  new_token->tok_app_count = 0;
  new_token->tok_apps = NULL;

  for ( i = 0; i < ret; ++i ) {
    jsmntok_t *token = tokens + i;
    switch ( state ) {
    case TOKEN_STATE_START:
      if ( token->type == JSMN_OBJECT ) {
        state = TOKEN_STATE_MAIN_OBJECT_KEY;
      } else {
        fprintf(stderr, "token_new_from_file: expected object at top-level\n");
        goto error;
      }
      break;

    case TOKEN_STATE_MAIN_OBJECT_KEY:
      if ( token->type == JSMN_STRING ) {
        if ( strncmp("permissions", buf + token->start, token->end - token->start) == 0 ) {
          state = TOKEN_STATE_MAIN_OBJECT_PERMISSIONS;
        } else if ( strncmp("applications", buf + token->start, token->end - token->start) == 0 ) {
          state = TOKEN_STATE_MAIN_OBJECT_APPLICATIONS;
        } else if ( strncmp("login_required", buf + token->start, token->end - token->start) == 0 ) {
          state = TOKEN_STATE_MAIN_OBJECT_LOGIN_REQUIRED;
        } else if ( strncmp("persona", buf + token->start, token->end - token->start) == 0 ) {
          fprintf(stderr, "Got persona key\n");
          state = TOKEN_STATE_MAIN_OBJECT_PERSONA;
        } else if ( strncmp("site", buf + token->start, token->end - token->start) == 0 ) {
          fprintf(stderr, "Got site key\n");
          state = TOKEN_STATE_MAIN_OBJECT_SITE;
        } else if ( strncmp("expiration", buf + token->start, token->end - token->start) == 0 ) {
          state = TOKEN_STATE_MAIN_OBJECT_EXPIRATION;
        } else if ( strncmp("secret", buf + token->start, token->end - token->start) == 0 ) {
          state = TOKEN_STATE_MAIN_OBJECT_SECRET;
        } else {
          fprintf(stderr, "token_new_from_file: invalid key in top-level object: %.*s\n",
                  token->end - token->start, buf + token->start);
          goto error;
        }
      } else {
        fprintf(stderr, "token_new_from_file: expected string as key of top-level object\n");
        goto error;
      }
      break;

    case TOKEN_STATE_MAIN_OBJECT_PERMISSIONS:
      if ( token->type == JSMN_ARRAY ) {
        if ( token->size > 0 ) {
          state = TOKEN_STATE_MAIN_OBJECT_IN_PERMISSIONS;

          if ( new_token->tok_perms_list || new_token->tok_perms_hash ) {
            fprintf(stderr, "token_new_from_file: duplicate key 'permissions'\n");
            goto error;
          }

          perm_count = token->size;
          new_token->tok_perms_list = malloc(sizeof(*new_token->tok_perms_list) * perm_count);
          if ( !new_token->tok_perms_list ) {
            fprintf(stderr, "token_new_from_file: could not allocate permissions\n");
            goto error;
          }
        } else
          state = TOKEN_STATE_MAIN_OBJECT_KEY;
      } else {
        fprintf(stderr, "token_new_from_file: expected array for 'permissions'\n");
        goto error;
      }
      break;

    case TOKEN_STATE_MAIN_OBJECT_APPLICATIONS:
      if ( token->type == JSMN_ARRAY ) {
        if ( token->size > 0 ) {
          state = TOKEN_STATE_MAIN_OBJECT_IN_APPLICATIONS;
          app_count = token->size;
          new_token->tok_apps = malloc(sizeof(*new_token->tok_apps) * app_count);
          if ( !new_token->tok_apps ) {
            fprintf(stderr, "token_new_from_file: could not allocate applications\n");
            goto error;
          }
        } else
          state = TOKEN_STATE_MAIN_OBJECT_KEY;
      } else {
        fprintf(stderr, "token_new_from_file: expected array for 'applications'\n");
        goto error;
      }
      break;

    case TOKEN_STATE_MAIN_OBJECT_LOGIN_REQUIRED:
      state = TOKEN_STATE_MAIN_OBJECT_KEY;
      if ( token->type == JSMN_PRIMITIVE && buf[token->start] == 't' ) {
        new_token->tok_flags |= TOKEN_FLAG_REQUIRES_LOGIN;
      } else if ( token->type == JSMN_PRIMITIVE && buf[token->start] == 'f' ) {
        new_token->tok_flags &= ~TOKEN_FLAG_REQUIRES_LOGIN;
      } else {
        fprintf(stderr, "token_new_from_file: expected true or false for 'login_required'\n");
        goto error;
      }
      break;

    case TOKEN_STATE_MAIN_OBJECT_PERSONA:
    case TOKEN_STATE_MAIN_OBJECT_SITE:
      if ( token->type == JSMN_STRING ) {
        const char *entity_type;
        unsigned char *dest;
        const char *digest;
        uint32_t flag;
        size_t digest_sz;

        if ( state == TOKEN_STATE_MAIN_OBJECT_PERSONA ) {
          entity_type = "persona";
          flag = TOKEN_FLAG_PERSONA_SPECIFIC;
          dest = (unsigned char *) new_token->tok_persona_id;
          digest = buf + token->start;

          if ( (token->end - token->start) != (PERSONA_ID_LENGTH * 2) ) {
            fprintf(stderr, "token_new_from_file: expected string of length %d for 'persona'\n",
                    PERSONA_ID_LENGTH * 2);
            goto error;
          }

          digest_sz = PERSONA_ID_LENGTH;
        } else {
          const char *colon;
          entity_type = "site";
          flag = TOKEN_FLAG_SITE_SPECIFIC;
          dest = (unsigned char *) new_token->tok_site_id;

          // Parse site type
          colon = memchr(buf + token->start, ':', token->end - token->start);
          if ( !colon ) {
            fprintf(stderr, "token_new_from_file: expected <digest>:<digesthex> in 'site' parameter\n");
            fprintf(stderr, "site was %.*s\n", (int)(token->end - token->start), buf + token->start);
            goto error;
          }
          digest = colon + 1;

          new_token->tok_site_digest = digest_scheme(buf + token->start,
                                                     colon - (buf + token->start));
          if ( !new_token->tok_site_digest ) {
            fprintf(stderr, "token_new_from_file: unknown digest type '%.*s'\n",
                    (int) (colon - (buf + token->start)), buf + token->start);
            goto error;
          }

          digest_sz = EVP_MD_size(new_token->tok_site_digest);
          if ( (buf + token->end - digest) != (digest_sz * 2) ) {
            fprintf(stderr, "token_new_from_file: expect %d hex characters for 'site' parameter in digest '%.*s'\n",
                    EVP_MD_size(new_token->tok_site_digest) * 2,
                    (int) (token->end - token->start), buf + token->start);
            goto error;
          }
        }
        state = TOKEN_STATE_MAIN_OBJECT_KEY;

        if ( !parse_hex_str(digest, dest, digest_sz) ) {
          fprintf(stderr, "token_new_from_file: invalid hex string for '%s'\n", entity_type);
          goto error;
        } else {
          new_token->tok_flags |= flag;
        }

      } else {
        fprintf(stderr, "token_new_from_file: expected string for 'persona'\n");
        goto error;
      }
      break;

    case TOKEN_STATE_MAIN_OBJECT_SECRET:
      if ( token->type == JSMN_STRING ) {
        if ( (token->end - token->start) < TOKEN_MIN_SECRET_LENGTH ) {
          fprintf(stderr, "token_new_from_file: not enough entroy in secret\n");
          goto error;
        } else {
          state = TOKEN_STATE_MAIN_OBJECT_KEY;
          has_secret = 1;
        }
      } else {
        fprintf(stderr, "token_new_from_file: expected random string in 'secret'\n");
        goto error;
      }
      break;

    case TOKEN_STATE_MAIN_OBJECT_EXPIRATION:
      state = TOKEN_STATE_MAIN_OBJECT_KEY;
      ((char *)buf)[token->end] = '\0';

      if ( token->type == JSMN_STRING &&
           sscanf(buf + token->start, "%04u-%02u-%02uT%02u:%02u:%02u.%6s",
                  &expiration.tm_year, &expiration.tm_mon, &expiration.tm_mday,
                  &expiration.tm_hour, &expiration.tm_min, &expiration.tm_sec,
                  microsecs) == 7 ) {
	fprintf(stderr, "Token expiration = %04d-%02d-%02d %02d:%02d:%02d\n",
		expiration.tm_year, expiration.tm_mon, expiration.tm_mday,
		expiration.tm_hour, expiration.tm_min, expiration.tm_sec);
	expiration.tm_year -= TM_YEAR_EPOCH;
        new_token->tok_expiration = mktime(&expiration);
        if ( new_token->tok_expiration < 0 ) {
          fprintf(stderr, "token_new_from_file: invalid time for 'expiration'\n");
          goto error;
        } else {
            new_token->tok_flags &= ~TOKEN_FLAG_NEVER_EXPIRES;
        }
      } else {
        fprintf(stderr, "token_new_from_file: invalid ISO8601 format string for 'expiration'\n");
        goto error;
      }
      break;

    case TOKEN_STATE_MAIN_OBJECT_IN_PERMISSIONS:
      if ( token->type == JSMN_STRING ) {
        struct perm *p = perm_find_perm_ex(buf + token->start, token->end - token->start);
        if ( !p ) {
          fprintf(stderr, "token_new_from_file: error finding permission %.*s\n",
                  token->end - token->start, buf + token->start);
          goto error;
        }

        new_token->tok_perms_list[new_token->tok_perm_count].tp_perm = p;
        HASH_ADD_KEYPTR(tp_hh, new_token->tok_perms_hash, p->perm_name, strlen(p->perm_name),
                        (new_token->tok_perms_list + new_token->tok_perm_count));

        new_token->tok_perm_count++;
        if ( perm_count == new_token->tok_perm_count )
          state = TOKEN_STATE_MAIN_OBJECT_KEY;

      } else {
        fprintf(stderr, "token_new_from_file: expected string for 'permission'\n");
        goto error;
      }
      break;

    case TOKEN_STATE_MAIN_OBJECT_IN_APPLICATIONS:
      if ( token->type == JSMN_STRING ) {
        char *app_name = malloc(token->end - token->start + 1);
        if ( !app_name ) {
          fprintf(stderr, "token_new_from_file: error allocating application name\n");
          goto error;
        }

        memcpy(app_name, buf + token->start, token->end - token->start);
        app_name[token->end - token->start] = '\0';

        new_token->tok_apps[new_token->tok_app_count++] = app_name;
        if ( app_count == new_token->tok_app_count )
          state = TOKEN_STATE_MAIN_OBJECT_KEY;
      } else {
        fprintf(stderr, "token_new_from_file: expected string for 'application'\n");
        goto error;
      }
      break;

    default:
      fprintf(stderr, "token_new_from_file: invalid token parsing state\n");
      goto error;
    }
  }

  if ( !has_secret ) {
    fprintf(stderr, "token_new_from_file: no 'secret' key in token\n");
    goto error;
  }

  if ( new_token->tok_perm_count == 0 ) {
    fprintf(stderr, "token_new_from_file: no permissions in token\n");
    goto error;
  }

  free((void *)buf);
  free(tokens);
  return new_token;

 error:
  if ( new_token ) TOKEN_UNREF(new_token);
  free((void *)buf);
  free(tokens);
  return NULL;
}

int token_check_permission(struct token *tok, const char *perm) {
  return token_check_permission_ex(tok, perm, strlen(perm));
}

int token_check_permission_ex(struct token *tok, const char *perm, size_t perm_sz) {
  struct tokenperm *found = NULL;

  // Tokens are immutable, so no need to lock
  HASH_FIND(tp_hh, tok->tok_perms_hash, perm, perm_sz, found);

  if ( found )
    return 0;
  else
    return -1;
}

int token_verify_hash(FILE *fl, const char *hash_hex, size_t hash_sz) {
  if ( hash_sz == (SHA256_DIGEST_LENGTH * 2)) {
    SHA256_CTX ctx;
    unsigned char hash[SHA256_DIGEST_LENGTH], act_hash[SHA256_DIGEST_LENGTH];
    char chunk[32];
    size_t bytes_read;

    if ( !parse_hex_str(hash_hex, hash, hash_sz / 2) ) {
      fprintf(stderr, "token_verify_hash: token hash must be a hex string\n");
      return -1;
    }

    if ( !SHA256_Init(&ctx) ) {
      fprintf(stderr, "token_verify_hash: could not initialize context\n");
      return -1;
    }

    while ( (bytes_read = fread(chunk, 1, sizeof(chunk), fl) ) ) {
      if ( !SHA256_Update(&ctx, chunk, bytes_read) ) {
        fprintf(stderr, "token_verify_hash: could not hash chunk\n");
        ERR_print_errors_fp(stderr);
        return -1;
      }
    }

    if ( ferror(fl) ) {
      fprintf(stderr, "token_verify_hash: could not read file\n");
      return -1;
    }

    assert(feof(fl));

    if ( !SHA256_Final(act_hash, &ctx) ) {
      fprintf(stderr, "token_verify_hash: could not finalize hash\n");
      return -1;
    }

    if ( memcmp(hash, act_hash, SHA256_DIGEST_LENGTH) == 0 ) {
      return 0;
    } else
      return -1;
  } else
    return -1;
}

int token_is_valid_now(struct token *tok) {
  if ( tok->tok_flags & TOKEN_FLAG_NEVER_EXPIRES )
    return 1;
  else {
    time_t now = time(NULL);
    return difftime(tok->tok_expiration, now) > 0;
  }
}
