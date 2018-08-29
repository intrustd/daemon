#include "client.h"

int fcs_init(struct flockclientstate *st, flockclientfn fn, shfreefn freefn) {
  SHARED_INIT(&st->fcs_shared, freefn);

  if ( !fn ) return -1;
  st->fcs_fn = fn;

  return 0;
}

void fsc_release(struct flockclientstate *st) {
}
