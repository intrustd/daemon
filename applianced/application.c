#include <sys/mount.h>
#include <sys/stat.h>
#include <uriparser/Uri.h>

#include "jsmn.h"
#include "application.h"
#include "persona.h"
#include "state.h"
#include "buffer.h"

#define OP_APPINSTANCE_RESET_REQUEST EVT_CTL_CUSTOM
#define OP_APPINSTANCE_RESET_COMPLETE (EVT_CTL_CUSTOM + 1)
#define OP_APPINSTANCE_FORCE_RESET (EVT_CTL_CUSTOM + 2)

static struct appmanifest *appmanifest_parse_tokens(const char *data, size_t sz,
                                                    jsmntok_t *tokens, int tokencnt);
static void freemanifest(const struct shared *sh, int level);

static int appinstance_setup(struct appinstance *ai);
static int appinstance_container_ctl(struct container *c, int op, void *argp, ssize_t argl);
static void appinstfn(struct eventloop *el, int op, void *arg);
static void freeinstfn(const struct shared *sh, int level);

int appmanifest_newer(struct appmanifest *new, struct appmanifest *old) {
  if ( memcmp(new->am_digest, old->am_digest, SHA256_DIGEST_LENGTH) == 0 )
    return 0;

  if ( new->am_major == old->am_major ) {
    if ( new->am_minor == old->am_minor ) {
      return new->am_revision > old->am_revision;
    } else
      return new->am_minor > old->am_minor;
  } else
    return new->am_major > old->am_major;
}


struct appmanifest *appmanifest_parse(const char *data, size_t data_sz) {
  jsmntok_t tokens[1024];
  int err, tokencnt;
  jsmn_parser parser;

  jsmn_init(&parser);

  err = tokencnt = jsmn_parse(&parser, data, data_sz, tokens, sizeof(tokens) / sizeof(tokens[0]));
  if ( err < 0 ) {
    switch ( err ) {
    case JSMN_ERROR_INVAL:
      fprintf(stderr, "appmanifest_parse: bad JSON\n");
      return NULL;
    case JSMN_ERROR_NOMEM:
      fprintf(stderr, "appmanifest_parse: manifest is too complicated\n");
      return NULL;
    case JSMN_ERROR_PART:
      fprintf(stderr, "appmanifest_parse: JSON ended while parsing\n");
      return NULL;
    default:
      return NULL;
    }
  }

  return appmanifest_parse_tokens(data, data_sz, tokens, tokencnt);
}

struct appmanifest *appmanifest_parse_from_file(const char *fn, unsigned char *exp_digest) {
  struct buffer b;
  struct appmanifest *mf;
  const char *data;
  size_t data_sz;
  unsigned char act_digest[SHA256_DIGEST_LENGTH];

  buffer_init(&b);
  if ( buffer_read_from_file(&b, fn) < 0 ) {
    buffer_release(&b);
    return NULL;
  }

  buffer_finalize(&b, &data, &data_sz);
  if ( !data ) return NULL;

  SHA256((unsigned char *)data, data_sz, act_digest);
  if ( memcmp(exp_digest, act_digest, sizeof(act_digest)) != 0 ) {
    free((void *)data);
    return NULL;
  }

  mf = appmanifest_parse(data, data_sz);
  free((void *) data);
  return mf;
}

#define EXPECT(what) do {                                               \
    fprintf(stderr, "Expected %s at %d\n", (what), token->start);       \
    goto error;                                                         \
  } while (0)
static struct appmanifest *appmanifest_parse_tokens(const char *data, size_t sz,
                                                    jsmntok_t *tokens, int tokencnt) {
  int i;
  enum {
    PARSING_ST_INITIAL,
    PARSING_ST_MAIN_OBJECT_KEY,
    PARSING_ST_CANONICAL,
    PARSING_ST_NAME,
    PARSING_ST_NIX_CLOSURE,
    PARSING_ST_SINGLETON,
    PARSING_ST_RUN_AS_ADMIN,
    PARSING_ST_BIND_MOUNTS
  } state = PARSING_ST_INITIAL;
  int main_obj_end = -1;

  struct appmanifest *ret;
  char *name = NULL, *canonical = NULL, *nix_closure = NULL;
  char **bind_mounts = NULL;

  size_t bind_mount_count = 0;
  uint32_t flags = 0;

  for ( i = 0; i < tokencnt; ++i ) {
    jsmntok_t *token = tokens + i;
    if ( main_obj_end > 0 && token->start > main_obj_end ) {
      fprintf(stderr, "Token after end of main object\n");
      goto error;
    }
    switch ( state ) {
    case PARSING_ST_INITIAL:
      if ( token->type != JSMN_OBJECT ) {
        EXPECT("object");
      } else {
        state = PARSING_ST_MAIN_OBJECT_KEY;
        main_obj_end = token->end;
      }
      break;
    case PARSING_ST_MAIN_OBJECT_KEY:
      if ( token->type != JSMN_STRING ) {
        EXPECT("string key");
      } else {
        if ( strncmp(data + token->start, "name", token->end - token->start) == 0 ) {
          state = PARSING_ST_NAME;
        } else if ( strncmp(data + token->start, "canonical", token->end - token->start) == 0 ) {
          state = PARSING_ST_CANONICAL;
        } else if ( strncmp(data + token->start, "nix-closure", token->end - token->start) == 0 ) {
          state = PARSING_ST_NIX_CLOSURE;
        } else if ( strncmp(data + token->start, "singleton", token->end - token->start) == 0 ) {
          state = PARSING_ST_SINGLETON;
        } else if ( strncmp(data + token->start, "runAsAdmin", token->end - token->start) == 0 ) {
          state = PARSING_ST_RUN_AS_ADMIN;
        } else if ( strncmp(data + token->start, "bind-mounts", token->end - token->start) == 0 ) {
          state = PARSING_ST_BIND_MOUNTS;
        } else {
          int end = -1;
          for ( ; i < tokencnt && (end < 0 || tokens[i].start < end); ++i ) {
            if ( end < 0 ) end = tokens[i].end;
          }
        }
      }
      break;

    case PARSING_ST_SINGLETON:
    case PARSING_ST_RUN_AS_ADMIN:
      if ( token->type != JSMN_PRIMITIVE ) {
        EXPECT("true or false");
      } else {
        int value;
        if ( data[token->start] == 't' ) {
          value = 1;
        } else if ( data[token->start] == 'f' ) {
          value = 0;
        } else
          EXPECT("boolean");

        if ( state == PARSING_ST_SINGLETON ) {
          if ( value ) flags |= APPMANIFEST_FLAG_SINGLETON;
          else flags &= ~APPMANIFEST_FLAG_SINGLETON;
        } else if ( state == PARSING_ST_RUN_AS_ADMIN ) {
          if ( value ) flags |= APPMANIFEST_FLAG_RUN_AS_ADMIN;
          else flags &= ~APPMANIFEST_FLAG_RUN_AS_ADMIN;
        }

        state = PARSING_ST_MAIN_OBJECT_KEY;
      }
      break;

    case PARSING_ST_CANONICAL:
    case PARSING_ST_NIX_CLOSURE:
    case PARSING_ST_NAME:
      if ( token->type != JSMN_STRING ) {
        EXPECT("string");
      } else {
        char **old, *this_name = "canonical" ;
        switch ( state ) {
        case PARSING_ST_CANONICAL: old = &canonical; this_name = "canonical"; break;
        case PARSING_ST_NAME: old = &name; this_name = "name"; break;
        case PARSING_ST_NIX_CLOSURE: old = &nix_closure; this_name = "nix-closure"; break;
        default: abort();
        }

        if ( *old ) {
          fprintf(stderr, "Duplicate %s at %d\n", this_name, token->start);
          goto error;
        }

        *old = malloc(token->end - token->start + 1);
        if ( !(*old) ) {
          fprintf(stderr, "out of memory\n");
          goto error;
        }

        memcpy(*old, data + token->start, token->end - token->start);
        (*old)[token->end - token->start] = '\0';

        state = PARSING_ST_MAIN_OBJECT_KEY;
      }
      break;

    case PARSING_ST_BIND_MOUNTS:
      if ( token->type != JSMN_ARRAY ) {
        EXPECT("list");
      } else {

        if ( bind_mounts ) {
          fprintf(stderr, "Duplicate bind-mounts\n");
          goto error;
        } else {
          jsmntok_t *bind_mount_tok;
          bind_mounts = malloc(sizeof(*bind_mounts) * token->size);
          if ( !bind_mounts ) {
            fprintf(stderr, "out of memory when allocating bind mounts\n");
            goto error;
          }

          bind_mount_count = token->size;
          memset(bind_mounts, 0, sizeof(*bind_mounts) * bind_mount_count);

          for ( ++ i ; i <= (token - tokens) + token->size; ++ i ) {
            bind_mount_tok = tokens + i;
            if ( bind_mount_tok->type != JSMN_STRING ) {
              EXPECT("string for bind-mount");
            } else {
              char *new_bind_mount;

              bind_mounts[i - (token - tokens) - 1] = new_bind_mount =
                malloc(bind_mount_tok->end - bind_mount_tok->start + 1);
              if ( !new_bind_mount ) {
                fprintf(stderr, "out of memory when creating bind mount\n");
                goto error;
              }

              memcpy(new_bind_mount, data + bind_mount_tok->start, bind_mount_tok->end - bind_mount_tok->start);
              new_bind_mount[bind_mount_tok->end - bind_mount_tok->start] = '\0';
            }
          }

          i -= 1;
          state = PARSING_ST_MAIN_OBJECT_KEY;
        }
      }
      break;

    default:
      fprintf(stderr, "Invalid state\n");
      goto error;
    }
  }

  if ( !name ) {
    fprintf(stderr, "No 'name' key given\n");
    goto error;
  }

  if ( !canonical ) {
    fprintf(stderr, "No 'canonical' url given\n");
    goto error;
  }

  if ( !nix_closure ) {
    fprintf(stderr, "No 'nix-closure' given\n");
    goto error;
  }

  if ( !validate_canonical_url(canonical, NULL, 0, NULL, 0) ) {
    fprintf(stderr, "Invalid canonical url\n");
    goto error;
  }

  ret = malloc(sizeof(*ret));
  if ( !ret ) goto error;

  if ( !SHA256((const unsigned char *)data, sz, ret->am_digest) ) {
    free(ret);
    goto error;
  }

  SHARED_INIT(&ret->am_shared, freemanifest);
  ret->am_flags = flags;
  ret->am_canonical = canonical;
  ret->am_name = name;
  ret->am_nix_closure = nix_closure;

  ret->am_bin_caches_count = 0;
  ret->am_bin_caches = NULL;

  ret->am_bind_mount_count = bind_mount_count;
  ret->am_bind_mounts = (const char **)bind_mounts;

  return ret;

 error:
  if ( name ) free(name);
  if ( canonical ) free(canonical);
  if ( nix_closure ) free(nix_closure);
  if ( bind_mounts ) {
    size_t i = 0;

    for ( i = 0; i < bind_mount_count; ++i ) {
      free(bind_mounts[i]);
    }

    free(bind_mounts);
  }
  return NULL;
}

static void freemanifest(const struct shared *sh, int level) {
  struct appmanifest *mf = STRUCT_FROM_BASE(struct appmanifest, am_shared, sh);
  if ( level == SHFREE_NO_MORE_REFS ) {
    if ( mf->am_canonical ) free((void *)mf->am_canonical);
    if ( mf->am_name ) free((void *)mf->am_name);
    if ( mf->am_nix_closure ) free((void *)mf->am_nix_closure);
    if ( mf->am_bin_caches ) free((void *)mf->am_bin_caches);

    if ( mf->am_bind_mounts ) {
      size_t i;

      for ( i = 0; i < mf->am_bind_mount_count; ++i ) {
        free((char *)mf->am_bind_mounts[i]);
      }

      free(mf->am_bind_mounts);
    }

    free(mf);
  }
}

int validate_canonical_url(const char *url, char *app_name, size_t app_name_sz,
                           char *app_domain, size_t app_domain_sz) {
  UriParserStateA uri_parser;
  UriUriA uri;

  uri_parser.uri = &uri;

  if ( uriParseUriA(&uri_parser, url) == URI_SUCCESS ) {
    int ret = 1;

    if ( !uri.scheme.first )
      ret = 0;

    if ( ret && strncmp(uri.scheme.first, APP_SCHEME, uri.scheme.afterLast - uri.scheme.first) != 0 )
      ret = 0;

    if ( ret && !uri.hostText.first )
      ret = 0;

    if ( ret && !uri.pathHead )
      ret = 0;

    if ( ret && (uri.pathHead != uri.pathTail) )
      ret = 0;

    if ( app_domain ) {
      strncpy_fixed(app_domain, app_domain_sz,
                    uri.hostText.first, uri.hostText.afterLast - uri.hostText.first);
    }

    if ( app_name ) {
      strncpy_fixed(app_name, app_name_sz,
                    uri.pathHead->text.first, uri.pathHead->text.afterLast - uri.pathHead->text.first);
    }

    uriFreeUriMembersA(&uri);
    return ret;
  } else
    return 0;
}

// application

static void application_freefn(const struct shared *sh, int lvl) {
  if ( lvl == SHFREE_NO_MORE_REFS ) {
    struct app *a = STRUCT_FROM_BASE(struct app, app_shared, sh);

    free(a->app_canonical_url);
    pthread_mutex_destroy(&a->app_mutex);
    APPMANIFEST_UNREF(a->app_current_manifest);

    free(a);
    // TODO close running instances
  }
}

struct app *application_from_manifest(struct appmanifest *mf) {
  struct app *ret = malloc(sizeof(*ret));
  if ( !ret ) return NULL;

  SHARED_INIT(&ret->app_shared, application_freefn);
  if ( pthread_mutex_init(&ret->app_mutex, NULL) != 0 ) {
    free(ret);
    return NULL;
  }

  ret->app_canonical_url = malloc(strlen(mf->am_canonical) + 1);
  if ( !ret->app_canonical_url ) {
    pthread_mutex_destroy(&ret->app_mutex);
    free(ret);
    return NULL;
  }
  strcpy(ret->app_canonical_url, mf->am_canonical);

  ret->app_flags = 0;
  APPMANIFEST_REF(mf);
  ret->app_current_manifest = mf;

  ret->app_instances = NULL;
  ret->app_singleton = NULL;

  return ret;
}

void application_unset_flags(struct app *a, uint32_t fs) {
  SAFE_MUTEX_LOCK(&a->app_mutex);
  a->app_flags &= ~fs;
  pthread_mutex_unlock(&a->app_mutex);
}

void application_set_flags(struct app *a, uint32_t fs) {
  SAFE_MUTEX_LOCK(&a->app_mutex);
  a->app_flags |= fs;
  pthread_mutex_unlock(&a->app_mutex);
}

void application_request_instance_resets(struct eventloop *el, struct app *a) {
  struct appinstance *cur, *tmp;
  HASH_ITER(inst_app_hh, a->app_instances, cur, tmp) {
    appinstance_request_reset(el, cur);
  }

  if ( a->app_singleton )
    appinstance_request_reset(el, a->app_singleton);
}

void appinstance_request_reset(struct eventloop *el, struct appinstance *ai) {
  APPINSTANCE_WREF(ai);
  if ( !eventloop_queue(el, &ai->inst_reset) ) {
    APPINSTANCE_WUNREF(ai);
  }
}

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

  qdevtsub_init(&ret->inst_reset, OP_APPINSTANCE_RESET_REQUEST, appinstfn);
  qdevtsub_init(&ret->inst_reset_complete, OP_APPINSTANCE_RESET_COMPLETE, appinstfn);
  timersub_init_default(&ret->inst_force_reset_timeout, OP_APPINSTANCE_FORCE_RESET, appinstfn);
  ret->inst_flags = 0;

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

static void appinstfn(struct eventloop *el, int op, void *arg) {
  struct appinstance *ai;
  struct qdevent *evt = (struct qdevent *) arg;

  switch ( op ) {
  case OP_APPINSTANCE_RESET_REQUEST:
    ai = STRUCT_FROM_BASE(struct appinstance, inst_reset, evt->qde_sub);

    if ( APPINSTANCE_LOCK(ai) == 0 ) {
      fprintf(stderr, "Performing app instance reset\n");
      SAFE_MUTEX_LOCK(&ai->inst_mutex);

      if ( (ai->inst_flags & APPINSTANCE_FLAG_RESETTING) == 0 ) {
	APPINSTANCE_WREF(ai);
	if ( container_stop(&ai->inst_container, el, &ai->inst_reset_complete) == 0 ) {
	  ai->inst_flags |= APPINSTANCE_FLAG_RESETTING;

	  APPINSTANCE_WREF(ai);
          timersub_set_from_now(&ai->inst_force_reset_timeout, APP_FORCE_RESET_TIMEOUT);
          eventloop_subscribe_timer(el, &ai->inst_force_reset_timeout);
	} else {
	  APPINSTANCE_WUNREF(ai);
	  fprintf(stderr, "appinstfn: unable to bring down container\n");
	}
      }

      pthread_mutex_unlock(&ai->inst_mutex);
      APPINSTANCE_UNREF(ai);
    }

    break;

  case OP_APPINSTANCE_RESET_COMPLETE:
    ai = STRUCT_FROM_BASE(struct appinstance, inst_reset_complete, evt->qde_sub);

    if ( APPINSTANCE_LOCK(ai) == 0 ) {
      int do_start = 0;
      SAFE_MUTEX_LOCK(&ai->inst_mutex);

      if ( ai->inst_flags & APPINSTANCE_FLAG_RESETTING ) {
        if ( eventloop_cancel_timer(el, &ai->inst_force_reset_timeout) ) {
          APPINSTANCE_WUNREF(ai);
        }

        ai->inst_flags &= ~APPINSTANCE_FLAG_RESETTING;

        do_start = 1;
      }

      pthread_mutex_unlock(&ai->inst_mutex);

      if ( do_start ) {
        // The reset is complete, so relaunch the container
        container_start(&ai->inst_container);
      }

      APPINSTANCE_UNREF(ai);
    }
    break;

  case OP_APPINSTANCE_FORCE_RESET:
    ai = STRUCT_FROM_BASE(struct appinstance, inst_force_reset_timeout, evt->qde_sub);
    if ( APPINSTANCE_LOCK(ai) == 0 ) {
      SAFE_MUTEX_LOCK(&ai->inst_mutex);

      if ( ai->inst_flags & APPINSTANCE_FLAG_RESETTING ) {
        // If resetting, then force this reset, by sending the init
        // process the kill signal.
        //
        // This will cause OP_APPINSTANCE_RESET_COMPLETE
        container_force_stop(&ai->inst_container);
      }

      pthread_mutex_unlock(&ai->inst_mutex);
      APPINSTANCE_UNREF(ai);
    }
    break;

  default:
    fprintf(stderr, "appinstfn: Unknown op %d\n", op);
  }
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
  const char *image_path;
  struct appmanifest *cur_mf;
  char path[PATH_MAX], app_name_or_path[PATH_MAX], app_domain[PATH_MAX],
    persona_id_str[PERSONA_ID_X_LENGTH + 1];
  int err;
  uint32_t app_flags = 0;

  if ( pthread_mutex_lock(&ai->inst_app->app_mutex) == 0 ) {
    fprintf(stderr, "appinstance_setup: read flags\n");
    app_flags = ai->inst_app->app_flags;
    cur_mf = ai->inst_app->app_current_manifest;
    image_path = ai->inst_app->app_current_manifest->am_nix_closure;

    fprintf(stderr, "appinstance: using closure %s (manifest %p)\n", image_path,
            ai->inst_app->app_current_manifest);
    pthread_mutex_unlock(&ai->inst_app->app_mutex);
  } else
    return -1;

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
    size_t i;

    FORMAT_PATH("%s/kite/appliance", image_path);
    err = mkdir_recursive(path);
    if ( err < 0 ) {
      perror("appinstance_setup: mkdir_recursive");
      fprintf(stderr, "appinstance_setup: while making %s\n", path);
    }

    DO_MOUNT(ai->inst_appstate->as_conf_dir, path, "bind", MS_BIND | MS_REC, "");

    // Also do any bind mounts
    for ( i = 0; i < cur_mf->am_bind_mount_count; ++i ) {
      FORMAT_PATH("%s%s", image_path, cur_mf->am_bind_mounts[i]);

      err = mkdir_recursive(path);
      if ( err < 0 ) {
        perror("appinstance_setup: mkdir_recursive");
        fprintf(stderr, "appinstance_setup: while bind mounting %s (making %s)\n", cur_mf->am_bind_mounts[i], path);
      }

      DO_MOUNT(cur_mf->am_bind_mounts[i], path, "bind", MS_BIND | MS_REC, "");
    }

    if ( bridge_mark_as_admin(&ai->inst_appstate->as_bridge,
                              ai->inst_container.c_bridge_port,
                              &ai->inst_container.c_arp_entry) < 0 ) {
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
