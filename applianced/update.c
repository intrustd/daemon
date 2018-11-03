#include <openssl/err.h>
#include <openssl/sha.h>
#include <uriparser/Uri.h>

#include "update.h"
#include "state.h"
#include "process.h"

#define OP_APPUPDATER_DL_PROGRESS EVT_CTL_CUSTOM
#define OP_APPUPDATER_PARSE_ASYNC (EVT_CTL_CUSTOM + 1)
#define OP_APPUPDATER_BUILD_PROCESS_EVENT (EVT_CTL_CUSTOM + 2)
#define OP_APPUPDATER_DL_SIGN_PROGRESS (EVT_CTL_CUSTOM + 3)

#define MF_TMPFILE_TEMPLATE "%s/manifests/.%08"PRIuPTR"-download.tmp"
#define MF_FINAL_TEMPLATE "%s/manifests/%s"
#define SIGN_SUFFIX ".sign"

static void appupdater_parse_manifest(struct appupdater *au);
static void appupdater_error(struct appupdater *au, int sts);
static void appupdater_build_from_manifest(struct appupdater *au);
static void appupdater_free(const struct shared *sh, int level);

static void appupdaterfn(struct eventloop *el, int op, void *arg) {
  struct appupdater *au;
  struct dlevent *dle;
  struct qdevent *qde;
  struct psevent *pse;

  switch ( op ) {
  case OP_APPUPDATER_BUILD_PROCESS_EVENT:
    pse = arg;
    au = STRUCT_FROM_BASE(struct appupdater, au_build_ps, pse->pse_sub);
    APPUPDATER_REF(au);
    if ( pse->pse_what & PSE_DONE ) {
      if ( au->au_application )
        application_unset_flags(au->au_application, APP_FLAG_UPDATING);
      if ( pse->pse_sts == 0 ) {
        int err;
        if ( au->au_application )
          err = appstate_update_app_from_manifest(au->au_appstate, au->au_application, au->au_manifest);
        else
          err = appstate_install_app_from_manifest(au->au_appstate, au->au_manifest);

        if ( err < 0 )
          appupdater_error(au, AU_STATUS_ERROR);
        else
          appupdater_error(au, AU_STATUS_DONE);
      } else {
        fprintf(stderr, "appupdaterfn: nix-build ended with status %d\n", pse->pse_sts);
        appupdater_error(au, AU_STATUS_ERROR);
      }
      pssub_release(&au->au_build_ps);
    }
    APPUPDATER_UNREF(au);
    break;

  case OP_APPUPDATER_PARSE_ASYNC:
    qde = arg;
    au = STRUCT_FROM_BASE(struct appupdater, au_parse_async, qde->qde_sub);
    appupdater_parse_manifest(au);
    break;

  case OP_APPUPDATER_DL_SIGN_PROGRESS:
    dle = arg;
    au = STRUCT_FROM_BASE(struct appupdater, au_sign_download, dle->dle_dl);

    if ( download_complete(dle->dle_dl) ) {
      fclose(au->au_sign_output);
      au->au_sign_output = NULL;

      if ( dle->dle_dl->dl_sts == DL_STATUS_NOT_FOUND ||
           dle->dle_dl->dl_sts >= 0 ) {
        au->au_sts = AU_STATUS_PARSING;
        eventloop_invoke_async(&au->au_appstate->as_eventloop, &au->au_parse_async);
      } else if ( dle->dle_dl->dl_sts < 0 ) {
        fprintf(stderr, "appupdater: %p: failed: %d\n", au, dle->dle_dl->dl_sts);;
        appupdater_error(au,AU_STATUS_ERROR);
      }
    } else {
      fprintf(stderr, "appupdater: %p: downloaded %zu/%zu bytes of signature\n",
              au, dle->dle_dl->dl_complete, dle->dle_dl->dl_total);
      if ( fwrite(dle->dle_dl->dl_buf, 1, dle->dle_dl->dl_bufsz, au->au_sign_output) !=
           dle->dle_dl->dl_bufsz ) {
        perror("fwrite(signature)");
        download_cancel(&au->au_sign_download);
        appupdater_error(au,AU_STATUS_ERROR);
      } else {
        download_continue(&au->au_sign_download);
      }
    }
    break;

  case OP_APPUPDATER_DL_PROGRESS:
    dle = arg;
    au = STRUCT_FROM_BASE(struct appupdater, au_download, dle->dle_dl);
    SAFE_MUTEX_LOCK(&au->au_mutex);
    if ( download_complete(dle->dle_dl) ) {
      if ( dle->dle_dl->dl_sts < 0 ) {
        fprintf(stderr, "appupdater: %p errored: %d\n", au, dle->dle_dl->dl_sts);
        appupdater_error(au, AU_STATUS_ERROR);
      } else {
        if ( au->au_application )
          application_unset_flags(au->au_application, APP_FLAG_DOWNLOADING_MFST);
        fprintf(stderr, "appupdater: %p complete\n", au);
        if ( !SHA256_Final(au->au_sha256_digest, &au->au_sha256_ctx) ) {
          fprintf(stderr, "appupdater: could not calculate digest\n");
          appupdater_error(au, AU_STATUS_ERROR);
        } else {
          char old_name[PATH_MAX], new_name[PATH_MAX];
          int err;

          fclose(au->au_output);
          au->au_output = NULL;

          err = snprintf(old_name, sizeof(old_name), MF_TMPFILE_TEMPLATE,
                         au->au_appstate->as_conf_dir, (uintptr_t)au);
          if ( err >= sizeof(old_name) ) {
            fprintf(stderr, "appupdate: overflowed path\n");
            appupdater_error(au, AU_STATUS_ERROR);
          }

          err = appupdater_manifest_path(au, new_name, sizeof(new_name));
          if ( err < 0 ) {
            fprintf(stderr, "appupdate: overflowed path\n");
            appupdater_error(au, AU_STATUS_ERROR);
          }

          if ( au->au_sts != AU_STATUS_ERROR ) {
            err = rename(old_name, new_name);
            if ( err < 0 ) {
              perror("appupdate: rename");
              appupdater_error(au, AU_STATUS_ERROR);
            } else {
              au->au_sts = AU_STATUS_DOWNLOADING_SIG;
            }
          }

          if ( au->au_sts == AU_STATUS_DOWNLOADING_SIG ) {
            err = snprintf(old_name, sizeof(old_name), "%s.sign", new_name);
            if ( err >= sizeof(old_name) ) {
              fprintf(stderr, "appupdater: overflowed path (signature)\n");
              appupdater_error(au, AU_STATUS_ERROR);
            } else {
              au->au_sign_output = fopen(old_name, "wb");
              if ( !au->au_sign_output ) {
                perror("appupdater: fopen(signature)");
                appupdater_error(au, AU_STATUS_ERROR);
              } else {
                download_start(&au->au_sign_download);
              }
            }
          }
        }
      }
    } else {
      fprintf(stderr, "appupdater: %p: downloaded %zu/%zu bytes\n", au,
              dle->dle_dl->dl_complete, dle->dle_dl->dl_total);
      if ( fwrite(dle->dle_dl->dl_buf, 1, dle->dle_dl->dl_bufsz, au->au_output) != dle->dle_dl->dl_bufsz ) {
        perror("fwrite");
        download_cancel(&au->au_download);
      } else {
        if ( !SHA256_Update(&au->au_sha256_ctx, dle->dle_dl->dl_buf, dle->dle_dl->dl_bufsz) ) {
          fprintf(stderr, "appupdater: could not compute sha256\n");
          ERR_print_errors_fp(stderr);
          download_cancel(&au->au_download);
        } else
          download_continue(&au->au_download);
      }
    }
    pthread_mutex_unlock(&au->au_mutex);
    break;

  default:
    fprintf(stderr, "appupdaterfn: unknown op %d\n", op);
  }
}

struct appupdater *appupdater_new(struct appstate *as, const char *uri, size_t uri_len,
                                  int reason, struct app *app) {
  UriParserStateA urip;
  UriUriA uri_uri, sign_uri;

  char output_path[PATH_MAX];
  int err;
  char *au_url, *au_sign_url;
  struct appupdater *u;

  urip.uri = &uri_uri;

  if ( uriParseUriExA(&urip, uri, uri + uri_len) != URI_SUCCESS ) {
    return NULL;
  } else {
    u = malloc(sizeof(*u));
    if ( !u ) return NULL;

    err = snprintf(output_path, sizeof(output_path), "%s/manifests", as->as_conf_dir);
    if ( err >= sizeof(output_path) ) {
      fprintf(stderr, "appupdater_new: manifests directory overflowed PATH_MAX\n");
      free(u);
      return NULL;
    }

    if ( mkdir_recursive(output_path) < 0 ) {
      perror("mkdir_recursive");
      fprintf(stderr, "appupdater_new: could not create %s\n", output_path);
      free(u);
      return NULL;
    }

    err = snprintf(output_path, sizeof(output_path), MF_TMPFILE_TEMPLATE,
                   as->as_conf_dir, (uintptr_t)u);
    if ( err >= sizeof(output_path) ) {
      fprintf(stderr, "appupdater_new: manifest path overflowed PATH_MAX\n");
      free(u);
      return NULL;
    }

    if ( pthread_mutex_init(&u->au_mutex, NULL) != 0 ) {
      free(u);
      return NULL;
    }

    memset(u->au_sha256_digest, 0, sizeof(u->au_sha256_digest));
    if ( !SHA256_Init(&u->au_sha256_ctx) ) {
      pthread_mutex_destroy(&u->au_mutex);
      free(u);
      return NULL;
    }

    SHARED_INIT(&u->au_shared, appupdater_free);

    u->au_output = NULL;
    u->au_sign_output = NULL;
    u->au_application = NULL;
    u->au_manifest = NULL;
    download_clear(&u->au_download);
    download_clear(&u->au_sign_download);
    u->au_url = au_url = malloc(uri_len + 1);
    if ( !u->au_url ) goto error;
    u->au_sign_url = au_sign_url = malloc(uri_len + strlen(SIGN_SUFFIX) + 1);
    if ( !u->au_sign_url ) goto error;

    memcpy(au_url, uri, uri_len);
    au_url[uri_len] = '\0';

    strcpy(au_sign_url, au_url);
    strcat(au_sign_url, SIGN_SUFFIX);

    urip.uri = &sign_uri;
    if ( uriParseUriExA(&urip, au_sign_url, au_sign_url + strlen(au_sign_url)) != URI_SUCCESS ) {
      fprintf(stderr, "appupdater_new: could not parse signature URL\n");
      goto error;
    }

    u->au_appstate = as;
    if ( app )
      APPLICATION_REF(app);
    u->au_application = app;
    u->au_reason = reason;
    u->au_force = 0;
    u->au_sts = AU_STATUS_WAITING;

    u->au_completion = NULL;

    u->au_output = fopen(output_path, "wb");
    if ( !u->au_output ) {
      perror("appupdater_new: fopen manifest");
      goto error;
    }

    if ( download_init(&u->au_download, &u->au_appstate->as_eventloop, &uri_uri,
                       OP_APPUPDATER_DL_PROGRESS, appupdaterfn) < 0 ) {
      fprintf(stderr, "appupdater_new: download_init error\n");
      goto error;
    }

    if ( download_init(&u->au_sign_download, &u->au_appstate->as_eventloop, &sign_uri,
                       OP_APPUPDATER_DL_SIGN_PROGRESS, appupdaterfn) < 0 ) {
      fprintf(stderr, "appupdater_new: download_init(signature) error\n");
      goto error;
    }

    qdevtsub_init(&u->au_parse_async, OP_APPUPDATER_PARSE_ASYNC, appupdaterfn);
    pssub_init(&u->au_build_ps, OP_APPUPDATER_BUILD_PROCESS_EVENT, appupdaterfn);
  }

  uriFreeUriMembersA(&uri_uri);
  return u;

 error:

  uriFreeUriMembersA(&uri_uri);
  appupdater_free(&u->au_shared, SHFREE_NO_MORE_REFS);
  return NULL;
}

void appupdater_free(const struct shared *sh, int level) {
  if ( level == SHFREE_NO_MORE_REFS ) {
    struct appupdater *au = STRUCT_FROM_BASE(struct appupdater, au_shared, sh);

    if ( au->au_application ) {
      APPLICATION_UNREF(au->au_application);
      au->au_application = NULL;
    }

    assert( evtqueue_is_empty(au->au_completion) );

    if ( au->au_url ) {
      free((void *)au->au_url);
      au->au_url = NULL;
    }

    if ( au->au_sign_url ) {
      free((void *)au->au_sign_url);
      au->au_sign_url = NULL;
    }

    download_release(&au->au_download);
    download_release(&au->au_sign_download);

    if ( au->au_output ) {
      fclose(au->au_output);
      au->au_output = NULL;
    }

    if ( au->au_sign_output ) {
      fclose(au->au_sign_output);
      au->au_sign_output = NULL;
    }

    if ( au->au_manifest ) {
      APPMANIFEST_UNREF(au->au_manifest);
      au->au_manifest = NULL;
    }

    pssub_release(&au->au_build_ps);

    pthread_mutex_destroy(&au->au_mutex);

    free(au);
  }
}

void appupdater_request_event(struct appupdater *au, struct qdevtsub *e) {
  SAFE_MUTEX_LOCK(&au->au_mutex);
  evtqueue_queue(&au->au_completion, e);
  pthread_mutex_unlock(&au->au_mutex);
}

void appupdater_start(struct appupdater *au) {
  SAFE_MUTEX_LOCK(&au->au_mutex);
  if ( au->au_sts == AU_STATUS_WAITING ) {
    au->au_sts = AU_STATUS_DOWNLOADING;
    if ( au->au_application )
      application_set_flags(au->au_application, APP_FLAG_DOWNLOADING_MFST);
    download_start(&au->au_download);
  }
  pthread_mutex_unlock(&au->au_mutex);
}

// Au mutex must be locked
int appupdater_manifest_path(struct appupdater *au, char *new_name, size_t new_name_size) {
  char digest_str[SHA256_DIGEST_LENGTH * 2 + 1];
  int err = snprintf(new_name, new_name_size, MF_FINAL_TEMPLATE,
                     au->au_appstate->as_conf_dir,
                     hex_digest_str(au->au_sha256_digest, digest_str, SHA256_DIGEST_LENGTH));
  if ( err >= new_name_size )
    return -1;
  else return 0;
}

static void appupdater_parse_manifest(struct appupdater *au) {
  struct buffer b;
  char mf_path[PATH_MAX];
  int err;
  const char *buf = NULL;
  struct app *cur_app;
  size_t bufsz;

  fprintf(stderr, "Parsing app manifest\n");

  err = appupdater_manifest_path(au, mf_path, sizeof(mf_path));
  if ( err < 0 ) {
    appupdater_error(au, AU_STATUS_ERROR);
    return;
  }

  err = buffer_read_from_file(&b, mf_path);
  if ( err < 0 ) {
    buffer_release(&b);
    appupdater_error(au, AU_STATUS_ERROR);
    return;
  }

  buffer_finalize(&b, &buf, &bufsz);
  if ( !buf ) {
    fprintf(stderr, "appupdater_parse_manifest: no manifest\n");
    appupdater_error(au, AU_STATUS_DONE);
    return;
  }

  au->au_manifest = appmanifest_parse(buf, bufsz);
  free((void *)buf);
  if ( !au->au_manifest ) {
    fprintf(stderr, "appupdater_parse_manifest: failed parse\n");
    appupdater_error(au, AU_STATUS_ERROR);
    return;
  }

  cur_app = appstate_get_app_by_url(au->au_appstate, au->au_manifest->am_canonical);
  if ( au->au_application && cur_app != au->au_application ) {
    fprintf(stderr, "appupdater_parse_manifest: manifest is for a different application\n");
    appupdater_error(au, AU_STATUS_ERROR);
  } else {
    if ( cur_app ) {
      if ( !au->au_application ) {
        APPLICATION_REF(cur_app);
        au->au_application = cur_app;
      }

      if ( appmanifest_newer(au->au_manifest, cur_app->app_current_manifest) ||
           au->au_force ) {
        au->au_sts = AU_STATUS_UPDATING;
        appupdater_build_from_manifest(au);
      } else {
        fprintf(stderr, "Marking done\n");
        appupdater_error(au, AU_STATUS_DONE);
      }

      APPLICATION_UNREF(cur_app);
    } else {
      au->au_sts = AU_STATUS_INSTALLING;
      // TODO use binary caches and nix closure to download the application
      appupdater_build_from_manifest(au);
    }
  }
}

static void appupdater_error(struct appupdater *au, int sts) {
  au->au_sts = sts;
  eventloop_queue_all(&au->au_appstate->as_eventloop, &au->au_completion);
}

static void appupdater_build_from_manifest(struct appupdater *au) {
  char log_path[PATH_MAX], mf_digest[SHA256_DIGEST_LENGTH * 2 + 1];
  FILE *stdout_log = NULL, *stderr_log = NULL;
  struct pssubopts ps;

  if ( au->au_application )
    application_set_flags(au->au_application, APP_FLAG_UPDATING);

  if ( appstate_log_path(au->au_appstate,
                         hex_digest_str(au->au_manifest->am_digest, mf_digest, SHA256_DIGEST_LENGTH),
                         NULL, log_path, sizeof(log_path)) < 0 ) {
    fprintf(stderr, "appupdater_build_from_manifest: could not fit log path\n");
    appupdater_error(au, AU_STATUS_ERROR);
    return;
  }

  if ( mkdir_recursive(log_path) < 0 ) {
    fprintf(stderr, "appupdater_build_from_manifest: could not make directory %s\n", log_path);
    appupdater_error(au, AU_STATUS_ERROR);
    return;
  }

  fprintf(stderr, "Made log path: %s\n", log_path);

  if ( appstate_log_path(au->au_appstate, mf_digest, "stdout.log", log_path, sizeof(log_path)) >= 0 ) {
    stdout_log = fopen(log_path, "wb");
    if ( !stdout_log )
      perror("fopen(stdout.log)");
  }

  if ( appstate_log_path(au->au_appstate, mf_digest, "stderr.log", log_path, sizeof(log_path)) >= 0 ) {
    stderr_log = fopen(log_path, "wb");
    if ( !stderr_log )
      perror("fopen(stderr.log)");
  }

  if ( !stdout_log || !stderr_log ) {
    fprintf(stderr, "appupdater_build_from_manifest: could not find stdout.log or stderr.log\n");
    if ( stdout_log ) fclose(stdout_log);
    if ( stderr_log ) fclose(stderr_log);
    appupdater_error(au, AU_STATUS_ERROR);
    return;
  }

  pssubopts_init(&ps);

  if ( pssubopts_pipe_to_file(&ps, PSSUB_STDOUT, stdout_log) < 0 ||
       pssubopts_pipe_to_file(&ps, PSSUB_STDERR, stderr_log) < 0 ) {
    pssubopts_release(&ps);
    fprintf(stderr, "appupdater_build_from_manifest: could not set up pipes\n");
    appupdater_error(au, AU_STATUS_ERROR);
    return;
  }

  pssubopts_set_command(&ps, "nix-store", NULL);
  pssubopts_push_arg(&ps, "nix-store", NULL);
  pssubopts_push_arg(&ps, "-r", NULL);
  pssubopts_push_arg(&ps, au->au_manifest->am_nix_closure, NULL);

  if ( au->au_manifest->am_bin_caches_count > 0 ) {
    int i;
    const char *data;
    struct buffer binary_caches;

    buffer_init(&binary_caches);

    pssubopts_push_arg(&ps, "--option", NULL);
    pssubopts_push_arg(&ps, "extra-binary-caches", NULL);

    for ( i = 0; i < au->au_manifest->am_bin_caches_count; ++i ) {
      if ( i == 0 )
        buffer_printf(&binary_caches, "%s", au->au_manifest->am_bin_caches[i]);
      else
        buffer_printf(&binary_caches, " %s", au->au_manifest->am_bin_caches[i]);
    }

    buffer_finalize_str(&binary_caches, &data);

    pssubopts_push_arg(&ps, data, free);
  }

  if ( pssubopts_error(&ps) ) {
    pssubopts_release(&ps);
    fprintf(stderr, "appupdater_build_from_manifest: could not set up build process\n");
    appupdater_error(au, AU_STATUS_ERROR);
    return;
  }

  if ( pssub_run_from_opts(&au->au_appstate->as_eventloop, &au->au_build_ps, &ps) < 0 ) {
    pssubopts_release(&ps);
    fprintf(stderr, "appupdater_build_from_manifest: could not launch nix build process\n");
    appupdater_error(au, AU_STATUS_ERROR);
    return;
  }

  pssubopts_release(&ps);
}
