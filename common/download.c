#include <errno.h>

#include "download.h"
#include "util.h"

#define OP_DL_ON_COMPLETE EVT_CTL_CUSTOM
#define OP_DL_ASYNC (EVT_CTL_CUSTOM + 1)
#define OP_DL_PROGRESS (EVT_CTL_CUSTOM + 2)

#define FLBUFSZ 1024

static void dlreadfile(struct download *dl) {
  fprintf(stderr, "dlreadfile: %s\n", dl->dl_target);
  if ( !dl->dl_fl ) {
    dl->dl_fl = fopen(dl->dl_target, "rb");
    if ( !dl->dl_fl ) {
      int olderr = errno;
      SAFE_MUTEX_LOCK(&dl->dl_mutex);
      if ( errno == ENOENT ) {
        dl->dl_sts = DL_STATUS_NOT_FOUND;
      } else {
        errno = olderr;
        perror("dlreadfile: fopen");
        dl->dl_sts = DL_STATUS_ERROR;
      }
      pthread_mutex_unlock(&dl->dl_mutex);
      eventloop_queue(dl->dl_eventloop, &dl->dl_on_complete);
      return;
    }

    if ( fseek(dl->dl_fl, 0, SEEK_END) != 0 ) {
      perror("dlreadfile: could not seek to end");
    } else {
      dl->dl_total = ftell(dl->dl_fl);
      if ( dl->dl_total < 0 ) {
        perror("dlreadfile: could not get end pos");
        dl->dl_total = 0;
      }

      fseek(dl->dl_fl, 0, SEEK_SET);
    }
  }

  if ( !feof(dl->dl_fl) ) {
    dl->dl_bufsz = fread(dl->dl_buf, 1,  FLBUFSZ, dl->dl_fl);
    if ( ferror(dl->dl_fl) ) {
      perror("fread");
      dl->dl_sts = DL_STATUS_ERROR;
      eventloop_queue(dl->dl_eventloop, &dl->dl_on_complete);
    } else {
      dl->dl_complete += dl->dl_bufsz;
      eventloop_queue(dl->dl_eventloop, &dl->dl_on_progress);
    }
  } else {
    dl->dl_sts = DL_STATUS_COMPLETE;
    fclose(dl->dl_fl);
    dl->dl_fl = NULL;
    eventloop_queue(dl->dl_eventloop, &dl->dl_on_progress);
  }
}

static void dlevtfn(struct eventloop *el, int op, void *arg) {
  struct qdevent *qde = arg;
  struct download *dl;

  struct dlevent dle;

  switch ( op ) {
  case OP_DL_ON_COMPLETE:
    dl = STRUCT_FROM_BASE(struct download, dl_on_complete, qde->qde_sub);
    dle.dle_dl = dl;
    dle.dle_type = DLE_EVENT_COMPLETE;
    dle.dle_buf = NULL;
    dle.dle_bufsz = 0;
    dl->dl_evtfn(el, dl->dl_op, &dle);
    break;

  case OP_DL_ASYNC:
    dl = STRUCT_FROM_BASE(struct download, dl_async, qde->qde_sub);
    fprintf(stderr, "dlevtfn: download async\n");
    switch ( dl->dl_type ) {
    case DL_TYPE_FILE:
      dlreadfile(dl);
      break;
    default:
      fprintf(stderr, "dlevtfn: OP_DL_ASYNC, but we don't need it for this scheme\n");
    }
    break;

  case OP_DL_PROGRESS:
    dl = STRUCT_FROM_BASE(struct download, dl_on_progress, qde->qde_sub);
    dle.dle_dl = dl;
    dle.dle_type = DLE_EVENT_COMPLETE;
    dle.dle_buf = dl->dl_buf;
    dle.dle_bufsz = dl->dl_bufsz;
    dl->dl_evtfn(dl->dl_eventloop, dl->dl_op, &dle);
    break;

  default:
    fprintf(stderr, "dlevtfn: unknown op %d\n", op);
  }
}

void download_clear(struct download *dl) {
  dl->dl_hdl = NULL;
  dl->dl_fl = NULL;
  dl->dl_buf = NULL;
  dl->dl_bufsz = 0;
  dl->dl_eventloop = NULL;
  dl->dl_complete = dl->dl_total = 0;
  dl->dl_sts = DL_STATUS_NOT_STARTED;
  dl->dl_op = 0;
  dl->dl_evtfn = NULL;
  dl->dl_type = DL_TYPE_UNKNOWN;
  dl->dl_target = NULL;
}

int download_init(struct download *dl, struct eventloop *el, UriUriA *uri,
                  int op, evtctlfn evtfn) {
  int urilen = 0;

  download_clear(dl);

  dl->dl_eventloop = el;
  dl->dl_op = op;
  dl->dl_evtfn = evtfn;

  if ( pthread_mutex_init(&dl->dl_mutex, NULL) != 0 )
    return -1;

  if ( uriToStringCharsRequiredA(uri, &urilen) != 0 ) {
    fprintf(stderr, "download_init: could not calculate uri length\n");
    goto error;
  }

  if ( uriNormalizeSyntaxA(uri) != 0 ) {
    fprintf(stderr, "download_init: could not normalize URI\n");
    goto error;
  }

  qdevtsub_init(&dl->dl_on_complete, OP_DL_ON_COMPLETE, dlevtfn);
  qdevtsub_init(&dl->dl_async, OP_DL_ASYNC, dlevtfn);
  qdevtsub_init(&dl->dl_on_progress, OP_DL_PROGRESS, dlevtfn);

  fprintf(stderr, "download_init: downloading scheme '%.*s'\n",
          (int) (uri->scheme.afterLast - uri->scheme.first), uri->scheme.first);

  if ( strncmp(uri->scheme.first, "file",
               uri->scheme.afterLast - uri->scheme.first) == 0 ) {
    char uri_str[urilen + 1], *uri_out;
    int uriwritten;

    if ( uriToStringA(uri_str, uri, urilen + 1, &uriwritten) != 0 ) {
      fprintf(stderr, "download_init: could not write uri str\n");
      goto error;
    }

    // File URI. We use our own handling because CURL is not asynchronous
    dl->dl_type = DL_TYPE_FILE;
    dl->dl_buf = malloc(FLBUFSZ);
    if( !dl->dl_buf ) {
      fprintf(stderr, "download_init: could not allocate file buffer\n");
      goto error;
    }
    dl->dl_bufsz = 0;

    dl->dl_target = uri_out = malloc(urilen + 1);
    if ( !dl->dl_target ) goto error;
    if ( uriUriStringToUnixFilenameA(uri_str, uri_out) != 0 ) {
      fprintf(stderr, "download_init: could not get filename\n");
      goto error;
    }
  } else {
    // Unrecognized URL
    fprintf(stderr, "download_init: unrecognized scheme '%.*s'\n",
            (int) (uri->scheme.afterLast - uri->scheme.first), uri->scheme.first);
    goto error;
  }

  return 0;

 error:
  download_release(dl);
  return -1;
}

void download_release(struct download *dl) {
  if ( dl->dl_target ) {
    free((void *)dl->dl_target);
    dl->dl_target = NULL;
  }

  if ( dl->dl_buf ) {
    free(dl->dl_buf);
    dl->dl_buf = NULL;
    dl->dl_bufsz = 0;
  }

  pthread_mutex_destroy(&dl->dl_mutex);
}

void download_start(struct download *dl) {
  SAFE_MUTEX_LOCK(&dl->dl_mutex);
  if ( dl->dl_sts != DL_STATUS_IN_PROGRESS ) {
    dl->dl_sts = DL_STATUS_IN_PROGRESS;
    switch ( dl->dl_type ) {
    case DL_TYPE_FILE:
      fprintf(stderr, "download_start: start invoke async\n");
      eventloop_invoke_async(dl->dl_eventloop, &dl->dl_async);
      break;
    default:
      fprintf(stderr, "download_start: unknown type %d\n", dl->dl_type);
      dl->dl_sts = DL_STATUS_ERROR;
      eventloop_queue(dl->dl_eventloop, &dl->dl_on_complete);
      break;
    }
  }
  pthread_mutex_unlock(&dl->dl_mutex);
}

void download_continue(struct download *dl) {
  SAFE_MUTEX_LOCK(&dl->dl_mutex);
  if ( dl->dl_sts == DL_STATUS_IN_PROGRESS ) {
    eventloop_invoke_async(dl->dl_eventloop, &dl->dl_async);
  }
  pthread_mutex_unlock(&dl->dl_mutex);
}

void download_cancel(struct download *dl) {
  SAFE_MUTEX_LOCK(&dl->dl_mutex);
  if ( dl->dl_sts == DL_STATUS_IN_PROGRESS ) {
    dl->dl_sts = DL_STATUS_CANCELLED;
  }
  pthread_mutex_unlock(&dl->dl_mutex);
}
