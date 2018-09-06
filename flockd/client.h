#ifndef __flock_client_H__
#define __flock_client_H__

#include "util.h"
#include "event.h"

struct flockservice;
struct flockclientstate;

struct fcspktwriter {
  DLIST(struct fcspktwriter) fcspw_dl;
  struct shared *fcspw_sh;
  int fcspw_sts;
  int (*fcspw_write)(struct fcspktwriter *, char *, int*);
  struct qdevtsub fcspw_done;
};

#define fcspktwriter_init(w, sh, writer, op, evtfn) do {        \
    DLIST_ENTRY_CLEAR(&(w)->fcspw_dl);                          \
    (w)->fcspw_sh = (sh);                                       \
    (w)->fcspw_sts = -1;                                        \
    (w)->fcspw_write = (writer);                                \
    qdevtsub_init(&(w)->fcspw_done, op, evtfn);                 \
  } while (0)

#define FCSPKTWRITER_FROM_EVENT(evt) STRUCT_FROM_BASE(struct fcspktwriter, fcspw_done, (evt)->qde_sub)

typedef void (*flockclientfn)(struct flockservice *, struct flockclientstate *, int op, void *arg);

struct flockclientstate {
  struct shared fcs_shared;
  flockclientfn fcs_fn;
};

int fcs_init(struct flockclientstate *st, flockclientfn fn, shfreefn freefn);
void fsc_release(struct flockclientstate *st);

#define FLOCKCLIENT_REF(cli) SHARED_REF(&(cli)->fcs_shared)
#define FLOCKCLIENT_UNREF(cli) SHARED_UNREF(&(cli)->fcs_shared)

#define FSC_RECEIVE_PKT 0x1

#endif
