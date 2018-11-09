#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include "util.h"
#include "persona.h"
#include "state.h"
#include "token.h"

#define SCTP_LOWEST_PRIVATE_PORT 49152

static void persona_release(struct persona *p);

// static int persona_ensure_container_running(struct persona *p);
// static int persona_release_container(struct persona *p);

static int appinstance_setup(struct appinstance *ai);
static int appinstance_container_ctl(struct container *c, int op, void *argp, ssize_t argl);
static void freeinstfn(const struct shared *sh, int level);

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
  p->p_auths = NULL;
  // p->p_ports = NULL;
  p->p_appstate = as;
  //  p->p_last_port = SCTP_LOWEST_PRIVATE_PORT;
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

static void persona_release(struct persona *p) {
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

static int pauth_verify(struct persona *persona, struct pconn *pc, struct pauth *p,
                        const char *cred, size_t cred_sz) {
  static const char pwd_prefix[] = { 'p', 'w', 'd', ':' };
  static const char token_prefix[] = { 't', 'o', 'k', 'e', 'n', ':' };

  unsigned char expected_sha256[SHA256_DIGEST_LENGTH];

  fprintf(stderr, "pauth_verify: %.*s\n", (int) cred_sz, cred);

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
    fprintf(stderr, "Verify token\n");
    // Check tokens
    if ( cred_sz > sizeof(token_prefix) &&
         memcmp(cred, token_prefix, sizeof(token_prefix)) == 0 ) {
      // A token is represented by <sha256sum>.<token signature>
      struct token *tok;
      const char *cred_start = cred + sizeof(token_prefix);
      const char *sign_start =
        memchr(cred_start, '.', cred_sz - sizeof(token_prefix));
      if ( !sign_start ) {
        fprintf(stderr, "pauth_verify: no signature in token\n");
        return 0;
      }

      fprintf(stderr, "Attempting to open token\n");
      tok = appstate_open_token_ex(persona->p_appstate,
                                   cred_start, sign_start - cred_start,
                                   sign_start + 1,
                                   cred + cred_sz - sign_start - 1);
      if ( !tok ) return 0;

      fprintf(stderr, "Checking token permission\n");
      // Check that the token has the login permission
      if ( token_check_permission(tok, TOKEN_LOGIN_PERM_URL) == 0 &&
           (tok->tok_flags & TOKEN_FLAG_PERSONA_SPECIFIC) &&
           memcmp(tok->tok_persona_id, persona->p_persona_id, PERSONA_ID_LENGTH) == 0 ) {
        // Save token and return
        if ( pconn_add_token_unlocked(pc, tok) == 0 ) {
          fprintf(stderr, "Token confirmed!\n");
          TOKEN_UNREF(tok);
          return 1;
        } else {
          TOKEN_UNREF(tok);
          return 0;
        }
      } else {
        fprintf(stderr, "Could not find login permission\n");
        TOKEN_UNREF(tok);
        return 0;
      }
    } else
      return 0;

  default:
    return 0;
  }
}

// pc mutex is locked
int persona_credential_validates(struct persona *p, struct pconn *pc,
                                 const char *cred, size_t cred_sz) {
  int ret = -1;
  struct pauth *auth;
  if ( pthread_mutex_lock(&p->p_mutex) == 0 ) {
    for ( auth = p->p_auths; auth; auth = auth->pa_next ) {
      if ( pauth_verify(p, pc, auth, cred, cred_sz) ) {
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

// static int personacontainerfn(struct container *c, int op, void *argp, ssize_t argl) {
//   struct persona *p = STRUCT_FROM_BASE(struct persona, p_container, c);
//   struct brpermrequest *perm;
//   const char **cp;
//   char *hostname, *persona_id;
//   int hostname_len, err;
//   char persona_id_str[PERSONA_ID_X_LENGTH];
// 
//   struct arpdesc *desc;
// 
//   switch ( op ) {
// 
//   case CONTAINER_CTL_DESCRIBE:
//     desc = argp;
//     desc->ad_container_type = ARP_DESC_PERSONA;
//     memcpy(desc->ad_persona.ad_persona_id, p->p_persona_id,
//            sizeof(desc->ad_persona.ad_persona_id));
//     return 0;
// 
//   case CONTAINER_CTL_CHECK_PERMISSION:
//     perm = argp;
//     if ( perm->bpr_perm.bp_type == BR_PERM_APPLICATION ) {
//       PERSONA_REF(p);
//       perm->bpr_persona = p;
//       return 0;
//     }
//     return -1;
// 
//   case CONTAINER_CTL_GET_TMP_PATH:
//     err = snprintf((char *) argp, argl, "%s/proc", p->p_appstate->as_conf_dir);
//     if ( err >= argl ) return -1;
//     else return 0;
// 
//   case CONTAINER_CTL_GET_INIT_PATH:
//     cp = argp;
//     *cp = p->p_appstate->as_persona_init_path;
//     return 0;
// 
//   case CONTAINER_CTL_GET_ARGS:
//     if ( argl < 1 ) {
//       fprintf(stderr, "personacontainerfn: not enough space for args\n");
//       return -1;
//     }
// 
//     cp = argp;
// 
//     cp[0] = persona_id = malloc(PERSONA_ID_X_LENGTH + 1);
//     if ( !cp[0] ) {
//       fprintf(stderr, "personacontainerfn: could not allocate argument 1\n");
//       return -1;
//     }
//     persona_id[PERSONA_ID_X_LENGTH] = '\0';
//     hex_digest_str((unsigned char *)p->p_persona_id, persona_id, PERSONA_ID_LENGTH);
//     return 1;
// 
//   case CONTAINER_CTL_GET_HOSTNAME:
//     cp = argp;
//     hostname_len = strlen(PERSONA_HOSTNAME_PREFIX) + 16; //PERSONA_ID_X_LENGTH;
//     *cp = hostname = malloc(hostname_len + 1);
//     if ( !(*cp) ) {
//       fprintf(stderr, "personacontainerfn: could not allocate hostname\n");
//       return -1;
//     }
// 
//     err = snprintf(hostname, hostname_len + 1, "%s%.16s", PERSONA_HOSTNAME_PREFIX,
//                    hex_digest_str((const unsigned char *)p->p_persona_id,
//                                   persona_id_str, PERSONA_ID_LENGTH));
//     assert(err == hostname_len);
//     (void)err;
// 
//     return 0;
// 
//   case CONTAINER_CTL_ON_SHUTDOWN:
//     PERSONA_UNREF(p);
//     return 0;
// 
//   case CONTAINER_CTL_RELEASE_INIT_PATH:
//     return 0;
//   case CONTAINER_CTL_RELEASE_ARG:
//   case CONTAINER_CTL_RELEASE_HOSTNAME:
//     free(argp);
//     return 0;
//   default:
//     fprintf(stderr, "personacontainerfn: unknown op %d\n", op);
//     return -2;
//   }
// }

// pid_t persona_run_ping_test(struct persona *p) {
//   const char *argv[] = { "ping", "10.0.0.1", NULL };
//   int err;
//   pid_t ret;
// 
//   err = persona_ensure_container_running(p);
//   if ( err < 0 ) {
//     fprintf(stderr, "persona_run_ping_test: could not launch\n");
//     return -1;
//   }
// 
//   ret = container_execute(&p->p_container, 0, "/run/wrappers/bin/ping", argv, NULL);
//   if ( ret < 0 )
//     persona_release_container(p);
// 
//   return ret;
// }
// 
// pid_t persona_run_webrtc_proxy(struct persona *p, uint16_t port) {
//   char port_str[16];
//   const char *argv[] = {
//     "webrtc-proxy", port_str, "TODO capability", NULL
//   };
//   int err;
//   pid_t ret;
// 
//   fprintf(stderr, "attempting to launch webRTC proxy on port %d\n", port);
// 
//   err = snprintf(port_str, sizeof(port_str), "%d", port);
//   assert(err < sizeof(port_str));
// 
//   err = persona_ensure_container_running(p);
//   if ( err < 0 ) {
//     fprintf(stderr, "persona_run_webrtc_proxy: could not launch persona container\n");
//     return -1;
//   }
// 
//   ret = container_execute(&p->p_container, CONTAINER_EXEC_WAIT_FOR_KITE,
//                           p->p_appstate->as_webrtc_proxy_path,
//                           argv, NULL);
//   if ( ret < 0 )
//     persona_release_container(p);
// 
//   return ret;
// }

// int persona_allocate_port(struct persona *p, uint16_t *port) {
//   *port = 0;
// 
//   if ( pthread_mutex_lock(&p->p_mutex) == 0 ) {
//     struct personaport *pp;
//     int ret = 0;
//     uint16_t attempts = 0;
// 
//     for ( attempts = 0; attempts < (0xFFFF - SCTP_LOWEST_PRIVATE_PORT); ++attempts ) {
//       p->p_last_port++;
//       if ( p->p_last_port < SCTP_LOWEST_PRIVATE_PORT )
//         p->p_last_port = SCTP_LOWEST_PRIVATE_PORT;
// 
//       HASH_FIND(pp_hh, p->p_ports, &p->p_last_port, sizeof(p->p_last_port), pp);
//       if ( !pp ) {
//         pp = malloc(sizeof(*pp));
//         if ( !pp ) {
//           fprintf(stderr, "persona_allocate_port: out of memory\n");
//           ret = -1;
//           goto done;
//         }
// 
//         pp->pp_port = p->p_last_port;
//         HASH_ADD(pp_hh, p->p_ports, pp_port, sizeof(pp->pp_port), pp);
// 
//         *port = pp->pp_port;
//         ret = 0;
//         goto done;
//       }
//     }
// 
//     ret = -1;
//   done:
//     pthread_mutex_unlock(&p->p_mutex);
//     return ret;
//   } else
//     return -1;
// }
// 
// void persona_release_port(struct persona *p, uint16_t port) {
//   struct personaport *pp;
//   SAFE_MUTEX_LOCK(&p->p_mutex);
//   HASH_FIND(pp_hh, p->p_ports, &port, sizeof(port), pp);
//   if ( pp ) {
//     HASH_DELETE(pp_hh, p->p_ports, pp);
//   }
//   pthread_mutex_unlock(&p->p_mutex);
// 
//   free(pp);
// }
// 
// static int persona_ensure_container_running(struct persona *p) {
//   int err;
// 
//   err = container_ensure_running(&p->p_container, &p->p_appstate->as_eventloop);
//   if ( err < 0 ) {
//     fprintf(stderr, "persona_ensure_container_running: container_ensure_running failed\n");
//     return -1;
//   }
// 
//   return err;
// }
// 
// static int persona_release_container(struct persona *p) {
//   return container_release_running(&p->p_container, &p->p_appstate->as_eventloop);
// }

struct appinstance *launch_app_instance(struct appstate *as, struct persona *p, struct app *a) {
  int singleton = 0;
  struct appinstance *ret;

  if ( pthread_mutex_lock(&a->app_mutex) == 0 ) {
    if ( a->app_flags & APP_FLAG_SINGLETON ) {
      fprintf(stderr, "Going to launch %s as singleton\n", a->app_canonical_url);
      if ( a->app_singleton ) {
        ret = a->app_singleton;
        APPINSTANCE_REF(ret);
        container_ensure_running(&ret->inst_container, &p->p_appstate->as_eventloop);
        pthread_mutex_unlock(&a->app_mutex);

        return ret;
      } else
        singleton = 1;
    } else if ( !p ) {
      fprintf(stderr, "cannot launch non-singleton app without persona\n");
      pthread_mutex_unlock(&a->app_mutex);
      return NULL;
    }
    pthread_mutex_unlock(&a->app_mutex);
  }

  if ( !singleton ) {
    assert(p);

    // Check if there is an instance available
    if ( pthread_mutex_lock(&p->p_mutex) == 0 ) {
      HASH_FIND(inst_persona_hh, p->p_instances,
                a->app_canonical_url,
                strlen(a->app_canonical_url),
                ret);
      if ( ret ) {
        APPINSTANCE_REF(ret);
        container_ensure_running(&ret->inst_container, &p->p_appstate->as_eventloop);
        pthread_mutex_unlock(&p->p_mutex);
        return ret;
      }
    } else
      return NULL;
  }

  ret = malloc(sizeof(*ret));
  SHARED_INIT(&ret->inst_shared, freeinstfn);
  if ( pthread_mutex_init(&ret->inst_mutex, NULL) != 0 ) {
    free(ret);
    return NULL;
  }

  ret->inst_appstate = as;

  APPLICATION_REF(a);
  ret->inst_app = a;

  if ( !singleton ) {
    PERSONA_REF(p);
    ret->inst_persona = p;
  } else
    ret->inst_persona = NULL;

  ret->inst_init_comm = -1;
  container_init(&ret->inst_container, &as->as_bridge, appinstance_container_ctl, 0);

  if ( pthread_mutex_lock(&a->app_mutex) == 0 ) {
    if ( p )
      HASH_ADD_KEYPTR(inst_persona_hh, p->p_instances,
                      a->app_canonical_url, strlen(a->app_canonical_url), ret);

    if ( singleton ) {
      a->app_singleton = ret;
    } else {
      HASH_ADD_KEYPTR(inst_app_hh, a->app_instances,
                      p->p_persona_id, PERSONA_ID_LENGTH, ret);
    }
    pthread_mutex_unlock(&a->app_mutex);

    // Start the container. The running container holds an instance of us
    APPINSTANCE_REF(ret);
    container_ensure_running(&ret->inst_container, &as->as_eventloop);
  } else {
    free(ret);
    ret = NULL;
  }

  if ( !singleton )
    pthread_mutex_unlock(&p->p_mutex);
  return ret;
}

static void freeinstfn(const struct shared *sh, int level) {
  if ( level == SHFREE_NO_MORE_REFS ) {
    struct appinstance *ai = STRUCT_FROM_BASE(struct appinstance, inst_shared, sh), *existing;

    if ( ai->inst_persona )
      SAFE_MUTEX_LOCK(&ai->inst_persona->p_mutex);

    SAFE_MUTEX_LOCK(&ai->inst_app->app_mutex);

    if ( ai->inst_persona ) {
      HASH_FIND(inst_persona_hh, ai->inst_persona->p_instances,
                ai->inst_app->app_canonical_url, strlen(ai->inst_app->app_canonical_url), existing);
      if ( existing == ai ) {
        HASH_DELETE(inst_persona_hh, ai->inst_persona->p_instances, existing);
      }


      HASH_FIND(inst_app_hh, ai->inst_app->app_instances,
                ai->inst_app->app_canonical_url, strlen(ai->inst_app->app_canonical_url), existing);
      if ( existing == ai ) {
        HASH_DELETE(inst_app_hh, ai->inst_app->app_instances, existing);
      }
      pthread_mutex_unlock(&ai->inst_app->app_mutex);
      pthread_mutex_unlock(&ai->inst_persona->p_mutex);
    } else {
      SAFE_ASSERT( ai->inst_app->app_singleton == ai );
      ai->inst_app->app_singleton = NULL;
      pthread_mutex_unlock(&ai->inst_app->app_mutex);
    }

    // The container will certainly be stopped, since a running container holds one ref
    if ( ai->inst_init_comm >= 0 ) {
      close(ai->inst_init_comm);
      ai->inst_init_comm = -1;
    }

    pthread_mutex_destroy(&ai->inst_mutex);

    APPLICATION_UNREF(ai->inst_app);

    if ( ai->inst_persona )
      PERSONA_UNREF(ai->inst_persona);

    free(ai);
  }
}

static int appinstance_container_ctl(struct container *c, int op, void *argp, ssize_t argl) {
  struct appinstance *ai = STRUCT_FROM_BASE(struct appinstance, inst_container, c);
  const char **cp;
  char *persona_id;

  struct arpdesc *desc;

  switch ( op ) {
  case CONTAINER_CTL_DESCRIBE:
    desc = argp;
    desc->ad_container_type = ARP_DESC_APP_INSTANCE;
    if ( ai->inst_persona ) {
      memcpy(desc->ad_app_instance.ad_persona_id, ai->inst_persona->p_persona_id,
             sizeof(desc->ad_app_instance.ad_persona_id));
    } else
      memset(desc->ad_app_instance.ad_persona_id, 0, sizeof(desc->ad_app_instance.ad_persona_id));
    strncpy(desc->ad_app_instance.ad_app_url, ai->inst_app->app_canonical_url,
            sizeof(desc->ad_app_instance.ad_app_url));
    desc->ad_app_instance.ad_app_instance = ai;
    APPINSTANCE_REF(ai);
    return 0;

  case CONTAINER_CTL_GET_INIT_PATH:
    cp = argp;
    *cp = ai->inst_appstate->as_app_instance_init_path;
    return 0;

  case CONTAINER_CTL_GET_ARGS:
    if ( argl < 3 ) {
      fprintf(stderr, "appinstance_container_ctl: not enough space for args\n");
      return -1;
    }

    cp = argp;
    if ( ai->inst_persona ) {
      cp[0] = persona_id = malloc(PERSONA_ID_X_LENGTH + 1);
      if ( !persona_id ) return -1;

      hex_digest_str((unsigned char *)ai->inst_persona->p_persona_id, persona_id, PERSONA_ID_LENGTH);
    } else
      cp[0] = "0000000000000000000000000000000000000000000000000000000000000000";

    cp[1] = ai->inst_app->app_canonical_url;
    cp[2] = ai->inst_app->app_current_manifest->am_nix_closure;
    return 3;

  case CONTAINER_CTL_GET_HOSTNAME:
    cp = argp;
    *cp = "app-instance"; // TODO
    return 0;

  case CONTAINER_CTL_ON_SHUTDOWN:
    APPINSTANCE_UNREF(ai);
    return 0;

  case CONTAINER_CTL_RELEASE_ARG:
    if ( argl == 0 )
      free((char *)argp);
    return 0;

  case CONTAINER_CTL_RELEASE_INIT_PATH:
  case CONTAINER_CTL_RELEASE_HOSTNAME:
    return 0;

  case CONTAINER_CTL_DO_SETUP:
    return appinstance_setup(ai);

  default:
    fprintf(stderr, "appinstance_container_ctl: unrecognized op %d\n", op);
    return -2;
  }
}

#define FORMAT_PATH(...) do {                                           \
    err = snprintf(path, sizeof(path), __VA_ARGS__);                    \
    if ( err >= sizeof(path) ) {                                        \
      fprintf(stderr, "appinstance_setup: could not write path\n");     \
      return -1;                                                        \
    }                                                                   \
  } while (0)
#define DO_MOUNT(dev, where, fsty, flags, opts) do {    \
    err = mount(dev, where, fsty, flags, opts);         \
    if ( err < 0 ) {                                    \
      perror("appinstance_setup: mount");                               \
      fprintf(stderr, "appinstance_setup: while mounting %s -> %s (type %s, options=%s)\n", \
              dev, where, fsty, opts);                                  \
      return -1;                                                        \
    }                                                                   \
  } while (0)
#define DO_MKDIR(where) do {                                            \
    err = mkdir(where, 0755);                                           \
    if ( err < 0 ) {                                                    \
      perror("appinstance_setup: mkdir");                               \
      fprintf(stderr, "appinstance_setup: while making %s\n", where);   \
    }                                                                   \
  } while (0)
static int appinstance_setup(struct appinstance *ai) {
  const char *image_path = ai->inst_app->app_current_manifest->am_nix_closure;
  char path[PATH_MAX], app_name_or_path[PATH_MAX], app_domain[PATH_MAX],
    persona_id_str[PERSONA_ID_X_LENGTH + 1];
  int err;
  uint32_t app_flags = 0;

  if ( pthread_mutex_lock(&ai->inst_app->app_mutex) == 0 ) {
    fprintf(stderr, "appinstance_setup: read flags\n");
    app_flags = ai->inst_app->app_flags;
    pthread_mutex_unlock(&ai->inst_app->app_mutex);
  }

  FORMAT_PATH("%s/nix", image_path);
  DO_MOUNT("/nix", path, "bind", MS_BIND | MS_RDONLY | MS_REC, "");

  FORMAT_PATH("%s/proc", image_path);
  DO_MOUNT("proc", path, "proc", 0, "");

  FORMAT_PATH("%s/dev", image_path);
  DO_MOUNT("tmpfs", path, "tmpfs", MS_NOSUID | MS_STRICTATIME, "mode=755,size=16384k");

  FORMAT_PATH("%s/run", image_path);
  DO_MOUNT("tmpfs", path, "tmpfs", MS_NOSUID | MS_STRICTATIME, "mode=700,size=16384k");

  FORMAT_PATH("%s/dev/pts", image_path);
  DO_MKDIR(path);
  DO_MOUNT("devpts", path, "devpts", MS_NOSUID | MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620,gid=0"); // TODO figure out group id

  FORMAT_PATH("%s/dev/shm", image_path);
  DO_MKDIR(path);
  DO_MOUNT("shm", path, "tmpfs", MS_NOSUID | MS_NOEXEC | MS_NODEV, "mode=1777,size=65536k");

  FORMAT_PATH("%s/dev/mqueue", image_path);
  DO_MKDIR(path);
  DO_MOUNT("mqueue", path, "mqueue", MS_NOSUID | MS_NOEXEC | MS_NODEV, "");

  FORMAT_PATH("%s/sys", image_path);
  DO_MOUNT("sysfs", path, "sysfs", MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_RDONLY, "");

  if ( ai->inst_persona ) {
    hex_digest_str((unsigned char *) ai->inst_persona->p_persona_id,
                   persona_id_str, PERSONA_ID_LENGTH);
  } else {
    memset(persona_id_str, '0', sizeof(persona_id_str));
    persona_id_str[PERSONA_ID_X_LENGTH] = '\0';
  }

  SAFE_ASSERT(validate_canonical_url(ai->inst_app->app_canonical_url,
                                     app_name_or_path, sizeof(app_name_or_path),
                                     app_domain, sizeof(app_domain)));
  FORMAT_PATH("%s/personas/%s/data/%s/%s", ai->inst_appstate->as_conf_dir,
              persona_id_str, app_domain, app_name_or_path);
  fprintf(stderr, "Made path %s\n", path);
  err = mkdir_recursive(path);
  if ( err < 0 ) {
    perror("appinstance_setup: mkdir_recursive");
    fprintf(stderr, "appinstance_setup: while making %s\n", path);
  }
  strcpy(app_name_or_path, path);

  FORMAT_PATH("%s/kite", image_path);
  DO_MOUNT(app_name_or_path, path, "bind", MS_BIND | MS_RDONLY | MS_REC, "");

  SAFE_ASSERT(validate_canonical_url(ai->inst_app->app_canonical_url,
                                     app_name_or_path, sizeof(app_name_or_path),
                                     app_domain, sizeof(app_domain)));
  FORMAT_PATH("%s/personas/%s/log/%s/%s", ai->inst_appstate->as_conf_dir,
              persona_id_str, app_domain, app_name_or_path);
  fprintf(stderr, "Making log path %s\n", path);
  err = mkdir_recursive(path);
  if ( err < 0 ) {
    perror("appinstance_setup: mkdir_recursive");
    fprintf(stderr, "appinstance_setup: while making %s\n", path);
  }
  strcpy(app_name_or_path, path);

  FORMAT_PATH("%s/var/log", image_path);
  DO_MOUNT(app_name_or_path, path, "bind", MS_BIND | MS_REC, "");

  // If this app has the 'run_with_admin' permission, then run this application with administrator privileges
  fprintf(stderr, "testing run as admin: %p %s %08x\n", ai->inst_app, ai->inst_app->app_canonical_url, app_flags);
  if ( app_flags & APP_FLAG_RUN_AS_ADMIN ) {
    FORMAT_PATH("%s/kite/appliance", image_path);
    err = mkdir_recursive(path);
    if ( err < 0 ) {
      perror("appinstance_setup: mkdir_recursive");
      fprintf(stderr, "appinstance_setup: while making %s\n", path);
    }

    DO_MOUNT(ai->inst_appstate->as_conf_dir, path, "bind", MS_BIND | MS_REC, "");

    if ( bridge_mark_as_admin(&ai->inst_appstate->as_bridge,
                              ai->inst_container.c_bridge_port,
                              ai->inst_container.c_arp_entry.ae_mac) < 0 ) {
      fprintf(stderr, "appinstance_setup: bridge_mark_as_admin fails\n");
    } else
      fprintf(stderr, "appinstance_setup: marked as admin\n");
  }

  if ( setenv("HOME", path, 1) < 0 ) {
    perror("setenv HOME");
  }

//  FORMAT_PATH("%s/sys/fs/cgroup", image_path);
//  DO_MOUNT("cgroup", path, "cgroup", MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_RELATIME | MS_RDONLY, "all");

  fprintf(stderr, "Launching app instance init\n");

  // the app-instance-init will change the root directory
  return 0;
}
