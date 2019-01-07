#include <errno.h>

#include "download.h"
#include "util.h"
#include "buffer.h"

#define OP_DL_ON_COMPLETE EVT_CTL_CUSTOM
#define OP_DL_ASYNC (EVT_CTL_CUSTOM + 1)
#define OP_DL_PROGRESS (EVT_CTL_CUSTOM + 2)

#define DATA_URI_BASE64_IND ";base64"
#define DATABUFSZ 15 // Must be divisible by 3
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

static int b64val(char c, unsigned int *v) {
  *v = 0;

  if ( c >= 'A' && c <= 'Z' ) {
    *v = c - 'A';
    return 0;
  } else if ( c >= 'a' && c <= 'z' ) {
    *v = c - 'a' + 26;
    return 0;
  } else if ( c >= '0' && c <= '9' ) {
    *v = c - '0' + 52;
    return 0;
  } else if ( c == '+' || c == '-' ) {
    *v = 63;
    return 0;
  } else if ( c == '/' || c == '_' ) {
    *v = 64;
    return 0;
  }

  return -1;
}

static int b64decchunk(char *out_buf, const char *in) {
  union {
    uint32_t out;
    char buf[4];
  } u;
  unsigned int v;
  int sz = 3;

  u.out = 0;

  if ( b64val(in[0], &v) < 0 ) return -1;
  u.out |= v << 18;

  if ( b64val(in[1], &v) < 0 ) return -1;
  u.out |= v << 12;

  if ( in[2] == '=' ) {
    if ( in[3] != '=' ) return -1;
    sz = 1;
  } else {
    if ( b64val(in[2], &v) < 0 ) return -1;
    u.out |= v << 6;

    if ( in[3] == '=' )
      sz = 2;
    else {
      if ( b64val(in[3], &v) < 0 ) return -1;
      u.out |= v;
    }
  }

  u.out = htonl(u.out);

  memcpy(out_buf, u.buf + 1, sz);
  return sz;
}

static void dlreadb64data(struct download *dl) {
  char buf[4];

  const char *in = dl->dl_target;
  int buf_i = 0, err;
  size_t buf_len = strlen(dl->dl_target);

  dl->dl_bufsz = 0;

  fprintf(stderr, "dlreadb64data: %zu %zu %zu\n", dl->dl_bufsz, dl->dl_offs, dl->dl_total);

  while ( dl->dl_bufsz < DATABUFSZ &&
          dl->dl_offs < buf_len ) {
    if ( in[dl->dl_offs] == '%' ) {
      if ( (dl->dl_total - dl->dl_offs) < 2 ) {
        dl->dl_sts = DL_STATUS_UNDERFLOW;
        eventloop_queue(dl->dl_eventloop, &dl->dl_on_complete);
        return;
      }

      err = parse_hex_str(in + dl->dl_offs + 1, (unsigned char *) buf + buf_i, 1);
      if ( err < 0 ) {
        fprintf(stderr, "dlreadb64data: invalid hex char %.*s", 2, in + dl->dl_offs + 1);
        dl->dl_sts = DL_STATUS_INVALID_ENCODING;
        eventloop_queue(dl->dl_eventloop, &dl->dl_on_complete);
        return;
      }

      buf_i ++;
      dl->dl_offs += 2;
    } else
      buf[buf_i++] = in[dl->dl_offs];

    dl->dl_offs++;

    if ( buf_i == 4 ) {
      // Do decode of this chunk
      err = b64decchunk(dl->dl_buf + dl->dl_bufsz, buf);
      if ( err < 0 ) {
        fprintf(stderr, "dlreadb64data: could not read chunk %.*s\n", 4, buf);
        dl->dl_sts = DL_STATUS_INVALID_ENCODING;
        eventloop_queue(dl->dl_eventloop, &dl->dl_on_complete);
        return;
      }

      buf_i = 0;
      dl->dl_bufsz += err;

      if ( err < 3 ) break;
    }
  }

  if ( buf_i > 0 ) {
    err = b64decchunk(dl->dl_buf + dl->dl_bufsz, buf);
    if ( err < 0 ) {
      fprintf(stderr, "dlreadb64data: could not read chunk %.*s (at end)\n", 4, buf);
      dl->dl_sts = DL_STATUS_INVALID_ENCODING;
      eventloop_queue(dl->dl_eventloop, &dl->dl_on_complete);
      return;
    }

    dl->dl_bufsz += err;
  }

  if ( dl->dl_bufsz > 0 ) {
    dl->dl_complete += dl->dl_bufsz;
    eventloop_queue(dl->dl_eventloop, &dl->dl_on_progress);
  } else {
    dl->dl_sts = DL_STATUS_COMPLETE;
    eventloop_queue(dl->dl_eventloop, &dl->dl_on_complete);
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
    case DL_TYPE_DATA:
      if ( dl->dl_complete < dl->dl_bufsz ) {
        dl->dl_complete += dl->dl_bufsz;
        eventloop_queue(dl->dl_eventloop, &dl->dl_on_progress);
      } else {
        dl->dl_sts = DL_STATUS_COMPLETE;
        eventloop_queue(dl->dl_eventloop, &dl->dl_on_complete);
      }
      break;
    case DL_TYPE_B64DATA:
      dlreadb64data(dl);
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
  } else if ( strncmp(uri->scheme.first, "data",
                      uri->scheme.afterLast - uri->scheme.first) == 0 ) {
    char *data_out, *type_end;
    const char *data_start;
    struct buffer b;
    UriPathSegmentA *p;
    const char *full_path;
    size_t path_sz;

    if ( !uri->pathHead || !uri->pathTail ) {
      fprintf(stderr, "download_init: No data for data: scheme\n");
      goto error;
    }

    buffer_init(&b);

    for ( p = uri->pathHead; p; p = p->next ) {
      buffer_printf(&b, "%s%.*s", p != uri->pathHead ? "/" : "",
                    (int) (p->text.afterLast - p->text.first),
                    p->text.first);
    }

    buffer_finalize(&b, &full_path, &path_sz);
    if ( !full_path ) {
      fprintf(stderr, "download_init: could not write path\n");
      goto error;
    }
    dl->dl_type = DL_TYPE_DATA;

    data_start = full_path;

    fprintf(stderr, "data url got path %.*s\n", (int)path_sz, full_path);

    if ( (type_end = memchr(full_path, ',', path_sz)) ) {
      data_start = type_end + 1;

      if ( (type_end - full_path) >= strlen(DATA_URI_BASE64_IND) &&
           memcmp(type_end - strlen(DATA_URI_BASE64_IND), DATA_URI_BASE64_IND, strlen(DATA_URI_BASE64_IND)) == 0 ) {
        type_end = type_end - strlen(DATA_URI_BASE64_IND);
        dl->dl_type = DL_TYPE_B64DATA;
        dl->dl_offs = 0;
      }

      fprintf(stderr, "download_init: got type %.*s\n", (int) (type_end - full_path), full_path);
    }

    dl->dl_target = dl->dl_buf = data_out = malloc(full_path + path_sz - data_start + 1);
    if ( !data_out ) {
      fprintf(stderr, "download_init: could not allocate data buf\n");
      goto error;
    }

    dl->dl_total = full_path + path_sz - data_start;

    memcpy(data_out, data_start, full_path + path_sz - data_start);
    data_out[full_path + path_sz - data_start] = '\0';

    fprintf(stderr, "Data url data is %s\n", data_out);

    if ( dl->dl_type == DL_TYPE_B64DATA ) {
      int adj = 0;

      dl->dl_buf = malloc(DATABUFSZ * 3);
      if ( !dl->dl_buf ){
        fprintf(stderr, "download_init: could not allocate data buf\n");
        goto error;
      }
      dl->dl_bufsz = full_path + path_sz - data_start;

      if ( dl->dl_total > 0 && dl->dl_target[dl->dl_total - 1] == '=') {
        adj ++;
        if ( dl->dl_total > 1 && dl->dl_target[dl->dl_total - 2] == '=' )
          adj++;
      }

      dl->dl_total = (dl->dl_total * 3) / 4;
      dl->dl_total -= adj;
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
  if ( dl->dl_target && dl->dl_target != dl->dl_buf ) {
    free((void *)dl->dl_target);
    dl->dl_target = NULL;
  }

  if ( dl->dl_buf ) {
    free(dl->dl_buf);
    if ( dl->dl_buf == dl->dl_target )
      dl->dl_target = NULL;
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
    case DL_TYPE_DATA:
    case DL_TYPE_B64DATA:
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
