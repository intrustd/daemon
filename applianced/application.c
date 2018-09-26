#include <uriparser/Uri.h>

#include "jsmn.h"
#include "application.h"
#include "buffer.h"

static struct appmanifest *appmanifest_parse_tokens(const char *data, size_t sz,
                                                    jsmntok_t *tokens, int tokencnt);
static void freemanifest(const struct shared *sh, int level);

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
  } state = PARSING_ST_INITIAL;
  int main_obj_end = -1;

  struct appmanifest *ret;
  char *name = NULL, *canonical = NULL, *nix_closure = NULL;

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
        } else {
          int end = -1;
          for ( ; i < tokencnt && (end < 0 || tokens[i].start < end); ++i ) {
            if ( end < 0 ) end = tokens[i].end;
          }
        }
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
  ret->am_canonical = canonical;
  ret->am_name = name;
  ret->am_nix_closure = nix_closure;

  ret->am_bin_caches_count = 0;
  ret->am_bin_caches = NULL;

  return ret;

 error:
  if ( name ) free(name);
  if ( canonical ) free(canonical);
  if ( nix_closure ) free(nix_closure);
  return NULL;
}

static void freemanifest(const struct shared *sh, int level) {
  struct appmanifest *mf = STRUCT_FROM_BASE(struct appmanifest, am_shared, sh);
  if ( level == SHFREE_NO_MORE_REFS ) {
    if ( mf->am_canonical ) free((void *)mf->am_canonical);
    if ( mf->am_name ) free((void *)mf->am_name);
    if ( mf->am_nix_closure ) free((void *)mf->am_nix_closure);
    if ( mf->am_bin_caches ) free((void *)mf->am_bin_caches);
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
                    uri.hostText.first, uri.hostText.afterLast - uri.hostText.first - 1);
    }

    if ( app_name ) {
      strncpy_fixed(app_name, app_name_sz,
                    uri.pathHead->text.first, uri.pathHead->text.afterLast - uri.pathHead->text.first - 1);
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

void application_request_instance_resets(struct app *a) {
  struct appinstance *cur, *tmp;
  HASH_ITER(inst_app_hh, a->app_instances, cur, tmp) {
    fprintf(stderr, "application_request_instance_resets: TODO");
    abort();
  }
}
