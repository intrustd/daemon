#include "personas.h"

// Personaswriter
int personaswriter_get_chunk(struct personaswriter *pw, char *out, int out_sz) {
  struct cpsreadargs r;
  int bytes_read;

  r.cpsra_buf = out;
  r.cpsra_sz = out_sz;
  r.cpsra_offs = pw->pw_offset;

  bytes_read = cps_read(pw->pw_cps, &r);

  if ( bytes_read > 0 )
    pw->pw_offset += bytes_read;

  return bytes_read;
}

void personaswriter_release(struct personaswriter *pw) {
  CPERSONASET_UNREF(pw->pw_cps);
  pw->pw_offset = 0;
  pw->pw_cps = NULL;
}

// cpersonaset
void cpersonaset_init(struct cpersonaset *cps, cpersonasetfn ctl, shfreefn do_free) {
  SHARED_INIT(&cps->cps_shared, do_free);
  cps->cps_fn = ctl;
}

// cmempersonaset
static void cmempersonaset_free(const struct shared *sh, int level) {
  struct cpersonaset *cps = STRUCT_FROM_BASE(struct cpersonaset, cps_shared, sh);
  struct cmempersonaset *cmps = STRUCT_FROM_BASE(struct cmempersonaset, cmps_cached, cps);

  if ( level == SHFREE_NO_MORE_REFS ) {
    const char *data;
    size_t data_sz;

    buffer_finalize(&cmps->cmps_buffer, &data, &data_sz);

    if ( data ) free((void *) data);

    free(cmps);
  }
}

static int cmempersonaset_ctl(struct cpersonaset *cps, int op, void *arg) {
  struct cmempersonaset *cmps = STRUCT_FROM_BASE(struct cmempersonaset, cmps_cached, cps);
  struct iovec *iov;
  struct cpersonaset **rp;
  struct cpsreadargs *read_args;

  switch ( op ) {
  case CPERSONASET_WRITE:
    iov = (struct iovec *) arg;
    if ( buffer_write(&cmps->cmps_buffer, iov->iov_base, iov->iov_len) < 0 )
      return -1;
    return 0;
  case CPERSONASET_GET_SIZE:
  case CPERSONASET_TELL:
    return cmps->cmps_buffer.b_size;
  case CPERSONASET_RCOMPLETE:
    return 0;
  case CPERSONASET_GET_READER:
    rp = (struct cpersonaset **) arg;
    *rp = cps;
    CPERSONASET_REF(*rp);
    return 0;
  case CPERSONASET_READ:
    read_args = (struct cpsreadargs *) arg;
    if ( read_args->cpsra_offs > cmps->cmps_buffer.b_size )
      return 0;
    if ( (read_args->cpsra_offs + read_args->cpsra_sz) > cmps->cmps_buffer.b_size )
      read_args->cpsra_sz = cmps->cmps_buffer.b_size - read_args->cpsra_offs;
    memcpy(read_args->cpsra_buf, cmps->cmps_buffer.b_data + read_args->cpsra_offs,
           read_args->cpsra_sz);
    return read_args->cpsra_sz;
  default:
    fprintf(stderr, "cmempersonaset_ctl: %p: Unknown op %d\n", cmps, op);
    return -2;
  }
}

struct cmempersonaset *cmempersonaset_alloc() {
  struct cmempersonaset *cmps = malloc(sizeof(*cmps));
  if ( !cmps ) return NULL;

  cpersonaset_init(&cmps->cmps_cached, cmempersonaset_ctl, cmempersonaset_free);
  buffer_init(&cmps->cmps_buffer);

  return cmps;
}

// Personasfetcher
int personasfetcher_init(struct personasfetcher *pf,
                         const unsigned char *hash,
                         struct cpersonaset *cache_entry,
                         personasfetcherfn fn,
                         shfreefn do_free) {
  SHARED_INIT(&pf->pf_shared, do_free);

  memcpy(pf->pf_hash, hash, sizeof(pf->pf_hash));

  evtqueue_init(&pf->pf_completion);
  pf->pf_is_complete = 0;

  pf->pf_cached = cache_entry;
  CPERSONASET_REF(cache_entry);
  pf->pf_control = fn;

  if ( pthread_mutex_init(&pf->pf_mutex, NULL) != 0 )
    return -1;

  return 0;
}

static void free_cached(const struct shared *sh, int level) {
  struct personasfetcher *ps = STRUCT_FROM_BASE(struct personasfetcher, pf_shared, sh);
  if ( level == SHFREE_NO_MORE_REFS ) {
    personasfetcher_release(ps);
    free(ps);
  }
}

static int pf_cached_ctl(struct personasfetcher *pf, int op, void *arg) {
  return -2; // Not implemented
}

struct personasfetcher *personasfetcher_new_from_cached(const unsigned char *hash,
                                                        struct cpersonaset *cache_entry,
                                                        struct eventloop *el) {
  struct personasfetcher *pf = malloc(sizeof(struct personasfetcher));
  if ( !pf ) return NULL;

  if ( personasfetcher_init(pf, hash, cache_entry, pf_cached_ctl, free_cached) < 0 ) {
    free(pf);
    return NULL;
  }

  personasfetcher_mark_complete(pf, el, 0);
  return pf;
}

void personasfetcher_release(struct personasfetcher *pf) {
  if ( pf->pf_cached ) {
    CPERSONASET_UNREF(pf->pf_cached);
    pf->pf_cached = NULL;
    pthread_mutex_destroy(&pf->pf_mutex);
  }
}

void personasfetcher_mark_complete(struct personasfetcher *pf, struct eventloop *el, int sts) {
  SAFE_MUTEX_LOCK(&pf->pf_mutex);
  if ( pf->pf_is_complete == 0 ) {
    pf->pf_is_complete = sts;
    eventloop_queue_all(el, &pf->pf_completion);
  }
  pthread_mutex_unlock(&pf->pf_mutex);
}

void personasfetcher_request_event(struct personasfetcher *pf, struct eventloop *el,
                                   struct qdevtsub *evt) {
  SAFE_MUTEX_LOCK(&pf->pf_mutex);
  if ( pf->pf_is_complete == 0 )
    evtqueue_queue(&pf->pf_completion, evt);
  else
    eventloop_queue(el, evt);
  pthread_mutex_unlock(&pf->pf_mutex);
}

int personasfetcher_init_personaswriter(struct personasfetcher *pf,
                                        struct personaswriter *w) {
  int ret = 0;
  if ( pthread_mutex_lock(&pf->pf_mutex) == 0 ) {
    if ( pf->pf_is_complete > 0 ) {
      w->pw_offset = 0;
      if ( cps_get_reader(pf->pf_cached, &w->pw_cps) < 0 )
        ret = -1;

      assert(w->pw_cps);
    } else
      ret = -1;
    pthread_mutex_unlock(&pf->pf_mutex);
    return ret;
  } else
    return -1;
}

