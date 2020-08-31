#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include "local_proto.h"
#include "util.h"
#include "persona.h"
#include "state.h"
#include "token.h"

#define SCTP_LOWEST_PRIVATE_PORT 49152

static void persona_release(struct persona *p);

// static int persona_ensure_container_running(struct persona *p);
// static int persona_release_container(struct persona *p);

void personacreateinfo_clear(struct personacreateinfo *pci) {
  pci->pci_displayname = pci->pci_password = NULL;
  pci->pci_displayname_sz = pci->pci_password_sz = 0;
  pci->pci_flags = 0;
  pci->pci_bump_avatar = 0;
}

static void personafreefn(const struct shared *sh, int level) {
  struct persona *p = STRUCT_FROM_BASE(struct persona, p_shared, sh);
  persona_release(p);

  if ( level == SHFREE_NO_MORE_REFS ) {
    free(p);
  }
}

static int persona_init_default(struct persona *p, struct appstate *as) {
  SHARED_INIT(&p->p_shared, personafreefn);
  p->p_private_key = NULL;
  p->p_display_name = NULL;
  p->p_photo_data = NULL;
  p->p_auths = NULL;
  // p->p_ports = NULL;
  p->p_appstate = as;
  //  p->p_last_port = SCTP_LOWEST_PRIVATE_PORT;
  p->p_flags = 0;
  p->p_instances = NULL;

  if ( pthread_mutex_init(&p->p_mutex, NULL) != 0 )
    return -1;

  return 0;
}

int persona_init(struct persona *p, struct appstate *as,
                 const char *display_name,
                 int display_name_sz,
                 EVP_PKEY *private_key) {
  if ( display_name_sz < 0 )
    display_name_sz = strlen(display_name);

  if ( persona_init_default(p, as) < 0 )
    return -1;

  p->p_private_key = private_key;

  p->p_display_name = malloc(display_name_sz + 1);
  if ( !p->p_display_name )
    return -1;

  memset(p->p_display_name, 0, display_name_sz + 1);
  strncpy(p->p_display_name, display_name, display_name_sz);
  p->p_display_name[display_name_sz] = 0;

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
  } else if ( strncmp(tys, "token", tye - tys) == 0 ) {
    auth->pa_type = PAUTH_TYPE_TOKEN;
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

int persona_init_fp(struct persona *p, struct appstate *as, FILE *fp) {
  char line[4096];
  int version = -1, i, st;

  char *attrs, *attre, *vls, *vle;

  if ( persona_init_default(p, as) < 0 )
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
        } else if ( st == PERSONA_PS_ATTRNM ) {
          attre = &line[i];
          vls = vle = NULL;
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
    } else if ( strncmp(attrs, "superuser", attre - attrs) == 0 ) {
      p->p_flags |= PERSONA_FLAG_SUPERUSER;
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

static void persona_release(struct persona *p) {
  struct pauth *a, *next;

  if ( p->p_private_key ) {
    EVP_PKEY_free(p->p_private_key);
    p->p_private_key = NULL;
  }

  if ( p->p_photo_data ) {
    free(p->p_photo_data);
    p->p_photo_data = NULL;
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

int persona_remove_passwords(struct persona *p) {
  struct pauth *prev = NULL, *cur;

  if ( pthread_mutex_lock(&p->p_mutex) < 0 )
    return -1;

  for ( cur = p->p_auths; cur; cur = cur->pa_next ) {
    if ( cur->pa_type == PAUTH_TYPE_SHA256 ) {
      if ( prev )
        prev->pa_next = cur->pa_next;
      else
        p->p_auths = cur->pa_next;

      free(cur);
    }
  }

  pthread_mutex_unlock(&p->p_mutex);

  return 0;
}

int persona_add_password(struct persona *p,
                         const char *password,
                         int password_sz) {
  struct pauth *new_auth = malloc(sizeof(*new_auth));
  SHA256_CTX c;

  if ( !new_auth ) return -1;

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

int persona_add_token_security(struct persona *p) {
  struct pauth *new_auth = malloc(sizeof(*new_auth));
  if ( !new_auth ) return -1;

  new_auth->pa_type = PAUTH_TYPE_TOKEN;

  if ( pthread_mutex_lock(&p->p_mutex) < 0 ) {
    free(new_auth);
    return -1;
  }

  new_auth->pa_next = p->p_auths;
  p->p_auths = new_auth;

  pthread_mutex_unlock(&p->p_mutex);

  return 0;
}

int persona_reset_password(struct persona *p, char *pw, size_t pw_sz) {
  persona_remove_passwords(p);
  return persona_add_password(p, pw, pw_sz);
}

int persona_set_photo_data_fp(struct persona *p, const char *mimetype, FILE *fp) {
  struct buffer b;
  char *old_data;

  buffer_init(&b);

  if ( buffer_printf(&b, "data:%s;base64,", mimetype) < 0 ) {
    buffer_release(&b);
    return -1;
  }

  while ( !feof(fp) ) {
    unsigned char chunk[3072];
    char b64_chunk[4096];
    size_t bytes_read = fread(chunk, 1, sizeof(chunk), fp), out_sz = sizeof(b64_chunk);

    if ( b64_encode(chunk, bytes_read, b64_chunk, &out_sz) < 0 ) {
      buffer_release(&b);
      return -1;
    }

    if ( buffer_write(&b, b64_chunk, out_sz) < 0 ) {
      buffer_release(&b);
      return -1;
    }

    if ( bytes_read < sizeof(chunk) )
      break;
  }

  if ( pthread_mutex_lock(&p->p_mutex) < 0 ) {
    buffer_release(&b);
    return -1;
  }

  old_data = p->p_photo_data;
  buffer_finalize_str(&b, (const char **)&p->p_photo_data);

  if ( old_data )
    free(old_data);

  pthread_mutex_unlock(&p->p_mutex);

  return 0;
}

int persona_unset_photo(struct persona *p) {
  char *old_data;

  if ( pthread_mutex_lock(&p->p_mutex) < 0 ) {
    return -1;
  }

  old_data = p->p_photo_data;
  p->p_photo_data = NULL;

  if ( old_data )
    free(old_data);

  pthread_mutex_unlock(&p->p_mutex);
  return 0;
}

int persona_set_display_name(struct persona *p, char *dn, size_t dn_sz) {
  char *new_dn = calloc(dn_sz + 1, 1), *old_dn;

  if ( !new_dn )
    return -1;

  memcpy(new_dn, dn, dn_sz);

  if ( pthread_mutex_lock(&p->p_mutex) < 0 ) {
    free(new_dn);
    return -1;
  }

  old_dn = p->p_display_name;
  p->p_display_name = new_dn;

  if ( old_dn )
    free(old_dn);

  pthread_mutex_unlock(&p->p_mutex);

  return 0;
}

int persona_save_fp(struct persona *p, FILE *fp) {
  struct pauth *a;
  char sha256buf[SHA256_DIGEST_LENGTH * 2 + 1];

  fprintf(fp, "persona 1\n"); // Versioning information
  if ( p->p_display_name )
    fprintf(fp, "displayname %s\n", p->p_display_name);

  if ( p->p_flags & PERSONA_FLAG_SUPERUSER )
    fprintf(fp, "superuser\n");

  // Auth methods
  for ( a = p->p_auths; a; a = a->pa_next ) {
    switch ( a->pa_type ) {
    case PAUTH_TYPE_SHA256:
      fprintf(fp, "auth sha256 %s\n", hex_digest_str((unsigned char *)a->pa_data, sha256buf, SHA256_DIGEST_LENGTH));
      break;
    case PAUTH_TYPE_TOKEN:
      fprintf(fp, "auth token\n");
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
  if ( buffer_printf(b, "X-INTRUSTDID:%s\n",
                     hex_digest_str((unsigned char *)p->p_persona_id,
                                    persona_id_hex,
                                    PERSONA_ID_LENGTH)) < 0 )
    return -1;

  if ( p->p_display_name ) {
    if ( buffer_printf(b, "FN:%s\n", p->p_display_name) < 0 )
      return -1;
  }

  if ( p->p_photo_data ) {
    if ( buffer_printf(b, "PHOTO:%s\n", p->p_photo_data) < 0 )
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

static const char pwd_prefix[] = { 'p', 'w', 'd', ':' };
static const char token_prefix[] = { 't', 'o', 'k', 'e', 'n', ':' };

static int pauth_verify(struct persona *persona, struct pconn *pc, struct pauth *p,
                        const char *cred, size_t cred_sz, int flags) {

  unsigned char expected_sha256[SHA256_DIGEST_LENGTH];

  //  fprintf(stderr, "pauth_verify: cred: %.*s\n", (int) cred_sz, cred);

  switch ( p->pa_type ) {
  case PAUTH_TYPE_SHA256:
    if ( cred_sz > sizeof(pwd_prefix) &&
         memcmp(cred, pwd_prefix, sizeof(pwd_prefix)) == 0 ) {
      SHA256((const unsigned char *)cred + sizeof(pwd_prefix), cred_sz - sizeof(pwd_prefix),
             expected_sha256);
      if ( memcmp(expected_sha256, p->pa_data, SHA256_DIGEST_LENGTH) == 0 ) {
          pc->pc_is_logged_in = 1; // Verified using username / password
          return 1;
      } else
        return 0;
    } else
      return 0;

  case PAUTH_TYPE_TOKEN:
    // Check tokens
    if ( cred_sz > sizeof(token_prefix) &&
         memcmp(cred, token_prefix, sizeof(token_prefix)) == 0 ) {
      // A token is represented by <sha256sum>.<token signature>
      struct token *tok;
      const char *cred_start = cred + sizeof(token_prefix);

      tok = appstate_open_token_ex(persona->p_appstate,
                                   cred_start, cred_sz - sizeof(token_prefix));
      if ( !tok ) return 0;

      // Check that the token has the login permission and is still valid
      if ( token_is_valid_now(tok) &&
           (pc->pc_state != PCONN_STATE_ESTABLISHED ||
            token_is_valid_for_site(tok, pc)) &&
           ((flags & PAUTH_FLAG_LOGIN) == 0 ||
            (token_check_permission(tok, TOKEN_LOGIN_PERM_URL) == 0 &&
             (tok->tok_flags & TOKEN_FLAG_PERSONA_SPECIFIC) &&
             memcmp(tok->tok_persona_id, persona->p_persona_id, PERSONA_ID_LENGTH) == 0)) ) {
        // Save token and return
        if ( pconn_add_token_unlocked(pc, tok) == 0 ) {
          TOKEN_UNREF(tok);
          return 1;
        } else {
          TOKEN_UNREF(tok);
          return 0;
        }
      } else {
        TOKEN_UNREF(tok);
        return 0;
      }
    } else
      return 0;

  default:
    return 0;
  }
}

// pc mutex should be locked
int persona_credential_validates(struct persona *p, struct pconn *pc,
                                 const char *cred, size_t cred_sz, int flag) {
  int ret = -1;
  struct pauth *auth;
  if ( pthread_mutex_lock(&p->p_mutex) == 0 ) {
    for ( auth = p->p_auths; auth; auth = auth->pa_next ) {
      if ( pauth_verify(p, pc, auth, cred, cred_sz, flag) ) {
        ret = 1;
        break;
      }
    }
    if ( !auth )
      ret = 0;
    pthread_mutex_unlock(&p->p_mutex);
  } else
    ret = -1;
  return ret;
}

// pc->pc_mutex must be held!
int persona_lookup_guest_credential(struct persona **p, struct pconn *pc,
                                    const char *cred, size_t cred_sz) {
  struct appstate *as = pc->pc_appstate;

  *p = NULL;

  if ( cred_sz > sizeof(token_prefix) &&
       memcmp(cred, token_prefix, sizeof(token_prefix)) == 0 ) {
    const char *cred_start = cred + sizeof(token_prefix);
    struct token *tok = appstate_open_token_ex(as, cred_start, cred_sz - sizeof(token_prefix));
    if ( !tok ) return 0;

    if ( token_is_valid_now(tok) &&
         (pc->pc_state != PCONN_STATE_ESTABLISHED ||
          token_is_valid_for_site(tok, pc)) &&
         token_check_permission(tok, TOKEN_GUEST_PERM_URL) == 0 &&
         (tok->tok_flags & TOKEN_FLAG_PERSONA_SPECIFIC) ) {
      // Lookup persona
      if ( appstate_lookup_persona(as, tok->tok_persona_id, p) == 0 ) {
        if ( pconn_add_token_unlocked(pc, tok) == 0 ) {
          TOKEN_UNREF(tok);
          return 1;
        } else {
          TOKEN_UNREF(tok);
          return 0;
        }
      } else {
        TOKEN_UNREF(tok);
        return 0;
      }
    } else {
      TOKEN_UNREF(tok);
      return 0;
    }
  } else
    return 0;
}
