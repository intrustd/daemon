#ifndef __flock_client_H__
#define __flock_client_H__

#include "util.h"
#include "service.h"

struct flockclientstate;

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
