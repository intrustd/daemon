#include "client.h"
#include "service.h"

int fcs_init(struct flockclientstate *st, flockclientfn fn, shfreefn freefn) {
  SHARED_INIT(&st->fcs_shared, freefn);

  if ( !fn ) return -1;
  st->fcs_fn = fn;

  return 0;
}

void fsc_release(struct flockclientstate *st) {
}

void fcspw_queue_fn(struct eventloop *el, int op, void *ev) {
  struct qdevent *qde = ev;
  struct fcspktwriter *pw;

  assert(op == EVT_CTL_CUSTOM);

  pw = STRUCT_FROM_BASE(struct fcspktwriter, fcspw_queue, qde->qde_sub);

  assert(pw->fcspw_do_queue);
  pw->fcspw_do_queue(pw);
}
