#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>
#include <ctype.h>

#include "util.h"
#include "persona.h"

static void personafreefn(const struct shared *sh, int level) {
  struct persona *p = STRUCT_FROM_BASE(struct persona, p_shared, sh);
  persona_release(p);

  if ( level == SHFREE_NO_MORE_REFS ) {
    free(p);
  }
}

static int persona_init_default(struct persona *p) {
  SHARED_INIT(&p->p_shared, personafreefn);
  p->p_private_key = NULL;
  p->p_display_name = NULL;
  p->p_auths = NULL;

  if ( pthread_mutex_init(&p->p_mutex, NULL) != 0 )
    return -1;

  return 0;
}

int persona_init(struct persona *p,
                 const char *display_name,
                 int display_name_sz,
                 EVP_PKEY *private_key) {
  if ( display_name_sz < 0 )
    display_name_sz = strlen(display_name);

  if ( persona_init_default(p) < 0 )
    return -1;

  p->p_private_key = private_key;

  p->p_display_name = malloc(display_name_sz + 1);
  if ( !p->p_display_name )
    return -1;

  strncpy(p->p_display_name, display_name, display_name_sz + 1);

  p->p_auths = NULL;

  return 0;
}

// Returns -1 on unrecoverable error, 0 on success, and 1 on an unknown auth method
static int persona_parse_auth(struct persona *p, char *vls, char *vle) {
  char *tys, *tye, *ds;
  struct pauth *auth;

  auth = malloc(sizeof(*auth));
  if ( !auth ) return -1;

  tys = vls;

  for ( tye = tys; tye != vle && !isspace(*tye); tye ++ );
  for ( ds = tye; ds != vle && isspace(*ds); ds++ );

  if ( strncmp(tys, "sha256", tye - tys) == 0 ) {
    auth->pa_type = PAUTH_TYPE_SHA256;
    if ( (vle - ds) == SHA256_DIGEST_LENGTH * 2 ) {
      if ( parse_hex_str(ds, (unsigned char *)auth->pa_data, SHA256_DIGEST_LENGTH) < 0 ) {
        fprintf(stderr, "persona_parse_auth: invalid sha256 auth hash: %.*s\n",
                (int)(vle - ds), ds);
        goto error;
      }
    } else {
      fprintf(stderr, "persona_parse_auth: expected %d characters for sha256 auth, got %d\n",
              SHA256_DIGEST_LENGTH * 2, (int)(vle - vls));
      goto error;
    }
  } else {
    fprintf(stderr, "persona_parse_auth: Unknown auth method '%.*s'\n", (int)(tye - tys), tys);
    free(auth);
    return 1;
  }

  if ( pthread_mutex_lock(&p->p_mutex) == 0 ) {
    auth->pa_next = p->p_auths;
    p->p_auths = auth;
    pthread_mutex_unlock(&p->p_mutex);
  } else {
    fprintf(stderr, "persona_parse_auth: could not lock\n");
    goto error;
  }

  return 0;

 error:
  free(auth);
  return -1;
}

#define PERSONA_PS_START        1
#define PERSONA_PS_ATTRNM       2
#define PERSONA_PS_AFTER_ATTRNM 3
#define PERSONA_PS_VAL          4
#define PERSONA_PS_END          5

int persona_init_fp(struct persona *p, FILE *fp) {
  char line[4096];
  int version = -1, i, st;

  char *attrs, *attre, *vls, *vle;

  if ( persona_init_default(p) < 0 )
    return -1;

  while ( fgets(line, sizeof(line), fp) ) {
    int sz = strlen(line);

    attrs = attre = NULL;
    vls = vle = NULL;

    st = PERSONA_PS_START;
    for ( i = 0; i < sz && st != PERSONA_PS_END ; ++i ) {
      if ( (line[i] == '\n' || line[i] == '\r') ) {
        if ( st == PERSONA_PS_VAL ) {
          vle = &line[i];
        } else {
          vls = vle = NULL;
        }
        break;
      }

      switch ( st ) {
      case PERSONA_PS_START:
        if ( !isspace(line[i]) ) {
          attrs = &line[i];
          st = PERSONA_PS_ATTRNM;
        }
        break;
      case PERSONA_PS_ATTRNM:
        if ( isspace(line[i]) ) {
          attre = &line[i];
          st = PERSONA_PS_AFTER_ATTRNM;
        }
        break;
      case PERSONA_PS_AFTER_ATTRNM:
        if ( !isspace(line[i]) ) {
          vls = &line[i];
          st = PERSONA_PS_VAL;
        }
        break;
      case PERSONA_PS_VAL:
        break;
      default:
        assert(0);
      };
    }

    if ( version == -1 ) {
      if ( strncmp(attrs, "persona", attre - attrs) == 0 ) {
        // Read version
        if ( atoi_ex(vls, vle, &version) < 0 ) {
          fprintf(stderr, "persona_init_fp: invalid version %.*s\n",
                  (int) (vle - vls), vls);
          goto error;
        }
      } else {
        persona_release(p);
        fprintf(stderr, "persona_init_fp: expected 'persona <version>' declaration\n");
        return -1;
      }
    } else if ( strncmp(attrs, "displayname", attre - attrs) == 0 ) {
      if ( vle == vls ) {
        fprintf(stderr, "persona_init_fp: attribute expected for 'displayname'\n");
        goto error;
      } else if ( p->p_display_name ) {
        fprintf(stderr, "persona_init_fp: duplicate 'displayname' attribute\n");
        goto error;
      } else {
        p->p_display_name = malloc(vle - vls + 1);
        if ( !p->p_display_name ) {
          fprintf(stderr, "persona_init_fp: out of memory for display name\n");
          goto error;
        }
        memcpy(p->p_display_name, vls, vle - vls);
        p->p_display_name[vle - vls] = '\0';
      }
    } else if ( strncmp(attrs, "auth", attre - attrs) == 0 ) {
      if ( persona_parse_auth(p, vls, vle) < 0 ) goto error;
    } else {
      fprintf(stderr, "persona_init_fp: unknown attribute %.*s for version %d\n",
              (int)(attre - attrs), attrs, version);
      goto error;
    }
  }

  return 0;

 error:
  persona_release(p);
  return -1;
}

void persona_release(struct persona *p) {
  struct pauth *a, *next;

  if ( p->p_private_key ) {
    EVP_PKEY_free(p->p_private_key);
    p->p_private_key = NULL;
  }

  if ( p->p_display_name ) {
    free(p->p_display_name);
    p->p_display_name = NULL;
    pthread_mutex_destroy(&p->p_mutex);
  }

  for ( a = p->p_auths, next = a ? a->pa_next : NULL;
        a; a = next, next = a ? a->pa_next : NULL ) {
    free(a);
  }
  p->p_auths = NULL;
}

int persona_add_password(struct persona *p,
                         const char *password,
                         int password_sz) {
  struct pauth *new_auth = malloc(sizeof(*new_auth));
  SHA256_CTX c;

  if ( password_sz < 0 )
    password_sz = strlen(password);

  if ( !SHA256_Init(&c) ) {
    free(new_auth);
    return -1;
  }

  if ( !SHA256_Update(&c, password, password_sz) ) {
    free(new_auth);
    return -1;
  }

  if ( !SHA256_Final((unsigned char *)new_auth->pa_data, &c) ) {
    free(new_auth);
    return -1;
  }

  new_auth->pa_type = PAUTH_TYPE_SHA256;

  if ( pthread_mutex_lock(&p->p_mutex) < 0 ) {
    free(new_auth);
    return -1;
  }

  new_auth->pa_next = p->p_auths;
  p->p_auths = new_auth;

  pthread_mutex_unlock(&p->p_mutex);

  return 0;
}

int persona_save_fp(struct persona *p, FILE *fp) {
  struct pauth *a;
  char sha256buf[SHA256_DIGEST_LENGTH * 2 + 1];

  fprintf(fp, "persona 1\n"); // Versioning information
  if ( p->p_display_name )
    fprintf(fp, "displayname %s\n", p->p_display_name);

  // Auth methods
  for ( a = p->p_auths; a; a = a->pa_next ) {
    switch ( a->pa_type ) {
    case PAUTH_TYPE_SHA256:
      fprintf(fp, "auth sha256 %s\n", hex_digest_str((unsigned char *)a->pa_data, sha256buf, SHA256_DIGEST_LENGTH));
      break;
    default:
      fprintf(stderr, "WARNING: persona_save_fp: unknown type %d\n", a->pa_type);
      break;
    }
  }

  return 0;
}

int persona_write_as_vcard(struct persona *p, struct buffer *b) {
  char persona_id_hex[PERSONA_ID_X_LENGTH + 1];

  if ( buffer_printf(b, "BEGIN:VCARD\n") < 0 ) return -1;
  if ( buffer_printf(b, "VERSION:4.0\n") < 0 ) return -1;
  if ( buffer_printf(b, "X-KITEID:%s\n",
                     hex_digest_str((unsigned char *)p->p_persona_id,
                                    persona_id_hex,
                                    PERSONA_ID_LENGTH)) < 0 )
    return -1;

  if ( p->p_display_name ) {
    if ( buffer_printf(b, "FN:%s\n", p->p_display_name) < 0 )
      return -1;
  }

  if ( buffer_printf(b, "END:VCARD\n") < 0 ) return -1;

  return 0;
}

// Persona set

void personaset_free(const struct shared *sh, int level) {
  struct personaset *ps = STRUCT_FROM_BASE(struct personaset, ps_shared, sh);

  if ( level != SHFREE_NO_MORE_REFS ) return;

  if ( ps->ps_buf ) {
    free((void *)ps->ps_buf);
    ps->ps_buf = NULL;
  }
  free(ps);
}

struct personaset *personaset_from_buf(const char *data, size_t sz) {
  struct personaset *ret = malloc(sizeof(*ret));
  if ( !ret ) return NULL;

  SHARED_INIT(&ret->ps_shared, personaset_free);

  SHA256((const unsigned char *) data, sz, ret->ps_hash);

  ret->ps_buf = data;
  ret->ps_buf_sz = sz;

  return ret;
}

static int pauth_verify(struct pauth *p, const char *cred, size_t cred_sz) {
  unsigned char expected_sha256[SHA256_DIGEST_LENGTH];

  switch ( p->pa_type ) {
  case PAUTH_TYPE_SHA256:
    SHA256((const unsigned char *)cred, cred_sz, expected_sha256);
    return memcmp(expected_sha256, p->pa_data, SHA256_DIGEST_LENGTH) == 0;
  default:
    return 0;
  }
}

int persona_credential_validates(struct persona *p, const char *cred, size_t cred_sz) {
  int ret = -1;
  struct pauth *auth;
  if ( pthread_mutex_lock(&p->p_mutex) == 0 ) {
    for ( auth = p->p_auths; auth; auth = auth->pa_next ) {
      if ( pauth_verify(auth, cred, cred_sz) ) {
        ret = 1;
        break;
      }
    }
    if ( !auth )
      ret = 0;
    fprintf(stderr, "After validation %d\n", ret);
    pthread_mutex_unlock(&p->p_mutex);
  } else
    ret = -1;
  return ret;
}
