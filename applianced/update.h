#ifndef __appliance_updater_H__
#define __appliance_updater_H__

#include <openssl/sha.h>
#include <uthash.h>

#include "event.h"
#include "process.h"
#include "download.h"

#define AU_UPDATE_REASON_AUTOMATIC 1
#define AU_UPDATE_REASON_MANUAL    2

#define AU_STATUS_ERROR (-2)
#define AU_STATUS_CANCELED (-1)
#define AU_STATUS_WAITING 0
#define AU_STATUS_DOWNLOADING 1
#define AU_STATUS_DOWNLOADING_SIG 2
#define AU_STATUS_PARSING 3
#define AU_STATUS_UPDATING 4
#define AU_STATUS_INSTALLING 5
#define AU_STATUS_DONE 6

struct appupdater {
  struct shared au_shared;

  pthread_mutex_t au_mutex;

  const char *au_url, *au_sign_url;
  UT_hash_handle au_hh;

  struct appstate* au_appstate;
  struct app *au_application;
  struct download au_download, au_sign_download;
  FILE *au_output, *au_sign_output;
  int au_reason;
  int au_force : 1;

  unsigned char au_sha256_digest[SHA256_DIGEST_LENGTH];
  SHA256_CTX au_sha256_ctx;

  int au_sts;

  evtqueue au_completion;
  struct qdevtsub au_completion_evt;

  struct appmanifest *au_manifest;
  struct qdevtsub au_parse_async;
  struct pssub au_build_ps;
};

#define APPUPDATER_FROM_COMPLETION_EVENT(arg) STRUCT_FROM_BASE(struct appupdater, au_completion_evt, ((struct qdevent *)arg)->qde_sub)

#define APPUPDATER_REF(au) SHARED_REF(&(au)->au_shared)
#define APPUPDATER_UNREF(au) SHARED_UNREF(&(au)->au_shared)

// appupdater
struct appupdater *appupdater_new(struct appstate *as, const char *uri, size_t uri_len,
                                  int reason, struct app *app);
#define appupdater_force(au) ((au)->au_force = 1)

void appupdater_start(struct appupdater *au);
void appupdater_request_event(struct appupdater *au, struct qdevtsub *e);
int appupdater_manifest_path(struct appupdater *au, char *new_name, size_t new_name_size);

#endif
