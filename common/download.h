#ifndef __kite_download_H__
#define __kite_download_H__

#include <uriparser/Uri.h>
#include <curl/curl.h>

#include "event.h"

#define DL_STATUS_IN_PROGRESS 0
#define DL_STATUS_COMPLETE 1
#define DL_STATUS_NOT_STARTED 2
#define DL_STATUS_ERROR (-1)
#define DL_STATUS_NOT_FOUND (-2)
#define DL_STATUS_CANCELLED (-3)


#define DL_TYPE_UNKNOWN 0
#define DL_TYPE_FILE    1

struct download {
  pthread_mutex_t dl_mutex;

  union {
    CURL *dl_hdl;
    FILE *dl_fl;
  };
  char *dl_buf;
  size_t dl_bufsz;

  const char *dl_target;

  struct eventloop *dl_eventloop;

  size_t dl_complete, dl_total;
  int dl_sts;
  unsigned int dl_type : 4;

  int dl_op;
  evtctlfn dl_evtfn;

  struct qdevtsub dl_on_complete;
  struct qdevtsub dl_async;
  struct qdevtsub dl_on_progress;
};

#define DLE_EVENT_PROGRESS 1
#define DLE_EVENT_COMPLETE 2
#define DLE_EVENT_DATA     3

struct dlevent {
  struct download *dle_dl;
  int dle_type;

  void *dle_buf;
  size_t dle_bufsz;
};

void download_clear(struct download *dl);
int download_init(struct download *dl, struct eventloop *el, UriUriA *uri,
                    int op, evtctlfn evtfn);
void download_start(struct download *dl);
void download_release(struct download *dl);

void download_cancel(struct download *dl);
void download_continue(struct download* dl);

// Only call when dl_mutex is locked
#define download_complete(dl) ((dl)->dl_sts == DL_STATUS_COMPLETE || (dl)->dl_sts < 0)

#endif
