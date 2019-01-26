#include <assert.h>
#include <stdio.h>

#include "appliance.h"
#include "service.h"
#include "util.h"

struct getpersonasrsp {
  const struct stuntxid *grs_tx_id;
  unsigned char *grs_personas_hash;
  uint32_t grs_offs, grs_length;
  uint32_t grs_payload_length;
  unsigned char *grs_payload;
};

static int aipersonasfetcher_init(struct aipersonasfetcher *aipf,
                                  const unsigned char *hash,
                                  struct cpersonaset *cache_entry,
                                  struct applianceinfo *info);
static void aipersonasfetcher_start(struct aipersonasfetcher *aipf,
                                    struct eventloop *el);
static void aipersonasfetcher_release(struct aipersonasfetcher *aipf);
static int aipf_write_pkt(struct fcspktwriter *pw, char *buf, int *sz);

int dummy_appliance_fn(struct applianceinfo *a, int o, void *r) {
  fprintf(stderr, "dummy_appliance_fn(%p, %d, %p)\n", a, o, r);
  return -1;
}

void applianceinfo_clear(struct applianceinfo *info) {
  info->ai_name[0] = '\0';
  info->ai_appliance_fn = dummy_appliance_fn;
  info->ai_flags = 0;
  info->ai_connections = 0;
  info->ai_fcs = NULL;
  memset(info->ai_personas, 0, sizeof(info->ai_personas));
}

int applianceinfo_init(struct applianceinfo *info, struct flockclientstate *fcs, shfreefn do_free) {
  applianceinfo_clear(info);

  assert(do_free);

  SHARED_INIT(&info->ai_shared, do_free);

  if ( pthread_mutex_init(&info->ai_mutex, NULL) != 0 ) {
    fprintf(stderr, "applianceinfo_init: could not initialize mutex\n");
    return -1;
  }
  info->ai_flags |= AI_FLAG_INITIALIZED;

  FLOCKCLIENT_REF(fcs);
  info->ai_fcs = fcs;

  return 0;
}

void applianceinfo_release(struct applianceinfo *info) {
  int i;

  for ( i = 0; i < sizeof(info->ai_personas) / sizeof(info->ai_personas[0]); ++i ) {
    if ( info->ai_personas[i] ) {
      PERSONASFETCHER_UNREF(info->ai_personas[i]);
    }
  }

  if ( info->ai_flags & AI_FLAG_INITIALIZED ) {
    pthread_mutex_destroy(&info->ai_mutex);
    info->ai_flags &= ~AI_FLAG_INITIALIZED;
  }

  if ( info->ai_fcs ) {
    FLOCKCLIENT_UNREF(info->ai_fcs);
    info->ai_fcs = NULL;
  }
}

#define AI_PERSONA_COUNT (sizeof(info->ai_personas) / sizeof(info->ai_personas[0]))
struct personasfetcher *applianceinfo_lookup_personas(struct applianceinfo *info,
                                                      struct eventloop *el,
                                                      struct flockservice *svc,
                                                      const unsigned char *hash) {
  struct personasfetcher *ret = NULL, *last = NULL;
  int i;

  if ( pthread_mutex_lock(&info->ai_mutex) == 0 ) {
    for (i = 0;
         i < AI_PERSONA_COUNT &&
           info->ai_personas[i] && !personasfetcher_hash_matches(info->ai_personas[i], hash);
         ++i);

    if ( i >= AI_PERSONA_COUNT ||
         !info->ai_personas[i] ) {
      // No match. Try to fetch a new persona
      struct cpersonaset *cache_entry;
      int sts;

      sts = flockservice_open_cached_personaset(svc, info->ai_name, hash,
                                                SHA256_DIGEST_LENGTH, &cache_entry);
      if ( sts == FLOCKSERVICE_CACHED_PERSONASET_FOUND ) {
        // The persona set was found in this cache entry. Return a
        // personasfetcher corresponding just to this cached entry
        ret =  personasfetcher_new_from_cached(hash, cache_entry, el);
      } else if ( sts == FLOCKSERVICE_CACHED_PERSONASET_NEW ) {
        // The entry returned needs to be written to
        ret = malloc(sizeof(struct aipersonasfetcher));
        if ( ret ) {
          if ( aipersonasfetcher_init((struct aipersonasfetcher *) ret, hash, cache_entry, info) < 0 ) {
            free(ret);
            ret = NULL;
          } else {
            if ( i >= AI_PERSONA_COUNT ) {
              last = info->ai_personas[AI_PERSONA_COUNT - 1];
              // Get rid of an old entry
              for ( i = 1; i < AI_PERSONA_COUNT; ++i )
                info->ai_personas[i] = info->ai_personas[i - 1];
            }

            info->ai_personas[0] = ret;
            PERSONASFETCHER_REF(ret);
            AI_WREF(info);

            aipersonasfetcher_start((struct aipersonasfetcher *) ret, el);
          }
        }
      } else {
        // cache lookup error
        ret = NULL;
        fprintf(stderr, "applianceinfo_lookup_personas: could not open cached entry\n");
      }
    } else {
      // Match
      ret = info->ai_personas[i];
      PERSONASFETCHER_REF(ret);
    }

    pthread_mutex_unlock(&info->ai_mutex);

    if ( last ) {
      personasfetcher_mark_complete(last, el, -1);
      PERSONASFETCHER_UNREF(last);
    }
    return ret;
  } else
    return NULL;
}

static void aipf_free(const struct shared *sh, int level) {
  struct personasfetcher *pf = STRUCT_FROM_BASE(struct personasfetcher, pf_shared, sh);
  struct aipersonasfetcher *aipf = STRUCT_FROM_BASE(struct aipersonasfetcher, aipf_fetcher, pf);

  if ( level == SHFREE_NO_MORE_REFS ) {
    aipersonasfetcher_release(aipf);
    free(aipf);
  } else {
    if ( aipf->aipf_el ) {
      if ( eventloop_cancel_timer(aipf->aipf_el, &aipf->aipf_req_timeout) )
        PERSONASFETCHER_WUNREF(pf);
    }

    if ( aipf->aipf_appliance ) {
      AI_WUNREF(aipf->aipf_appliance);
      aipf->aipf_appliance = NULL;
    }
  }
}

static void aipersonasfetcher_send_packet(struct aipersonasfetcher *aipf) {
  struct applianceinfo *app;

  SAFE_MUTEX_LOCK(&aipf->aipf_fetcher.pf_mutex);
  app = aipf->aipf_appliance;
  assert(app);
  AI_REF(app);
  SAFE_MUTEX_UNLOCK(&aipf->aipf_fetcher.pf_mutex);

  fprintf(stderr, "aipersonasfetcher_start: sending packet\n");
  AI_WREF(app);
  if ( applianceinfo_ctl(app, AI_OP_SEND_PACKET, &aipf->aipf_pkt_writer) < 0 ) {
    AI_WUNREF(app);
    fprintf(stderr, "aipersonasfetcher_start: warning could not send packet\n");
  }

  AI_UNREF(app);
}

static void aipersonasfetcher_failed(struct aipersonasfetcher *aipf) {
  stun_random_tx_id(&aipf->aipf_tx_id);
  personasfetcher_mark_complete(&aipf->aipf_fetcher, aipf->aipf_el, -1);
  fprintf(stderr, "TODO aipersonasfetcher_failed: (should signal applianceinfo)\n");
}

#define OP_AIPF_REQ_TIMEOUT      EVT_CTL_CUSTOM
#define OP_AIPF_PKT_WRITTEN      (EVT_CTL_CUSTOM + 1)
static void aipersonasfetcher_evtfn(struct eventloop *el, int op, void *arg) {
  struct aipersonasfetcher *this;
  struct qdevent *evt = (struct qdevent *) arg;

  switch ( op ) {
  case OP_AIPF_PKT_WRITTEN:
    fprintf(stderr, "aipersonasfetcher_evtfn: sent packet\n");
    this = STRUCT_FROM_BASE(struct aipersonasfetcher, aipf_pkt_writer, FCSPKTWRITER_FROM_EVENT(evt));

    if ( AIPF_LOCK(this) == 0 ) {
      if ( !eventloop_cancel_timer(el, &this->aipf_req_timeout) )
        AIPF_WREF(this); // If the timer was not set, then acquire a weak reference for it
      timersub_set_from_now(&this->aipf_req_timeout, AI_PERSONAS_FETCH_RETRY_INTERVAL << this->aipf_req_retries);
      eventloop_subscribe_timer(el, &this->aipf_req_timeout);
      AIPF_UNREF(this);
    }

    break;
  case OP_AIPF_REQ_TIMEOUT:
    fprintf(stderr, "aipersonasfetcher_evtfn: timeout... resending\n");
    this = STRUCT_FROM_BASE(struct aipersonasfetcher, aipf_req_timeout, evt->qde_sub);

    if ( AIPF_LOCK(this) == 0 ) {
      if ( this->aipf_fetcher.pf_is_complete ) {
        fprintf(stderr, "aipersonasfetcher_evtfn: timeout... but we're complete!\n");
      } else {
        this->aipf_req_retries++;
        if ( this->aipf_req_retries >= AI_PERSONAS_FETCH_MAX_RETRIES ) {
          aipersonasfetcher_failed(this);
        } else
          aipersonasfetcher_send_packet(this);
      }
      AIPF_UNREF(this);
    }
    break;
  default:
    fprintf(stderr, "aipersonasfetcher_evtfn: Unknown op %d\n", op);
  };
}

static int aipf_control(struct personasfetcher *pf, int op, void *arg) {
  struct getpersonasrsp *grs;
  struct aipersonasfetcher *aipf = STRUCT_FROM_BASE(struct aipersonasfetcher, aipf_fetcher, pf);
  int actual_ofs, ret = 0, should_request_send = 0, has_completed = 0;

  switch ( op ) {
  case PF_OP_AIPF_RECEIVE_STUN:
    grs = (struct getpersonasrsp *) arg;
    AIPF_REF(aipf);
    fprintf(stderr, "aipf_control: received stun: %.*s\n", grs->grs_payload_length, grs->grs_payload);

    SAFE_MUTEX_LOCK(&pf->pf_mutex);
    if ( memcmp(&aipf->aipf_tx_id, grs->grs_tx_id, sizeof(aipf->aipf_tx_id)) == 0 ) {
      assert(pf->pf_cached);
      actual_ofs = cps_tell(pf->pf_cached);

      fprintf(stderr, "aipf_control: accepted stun: %d %d\n", actual_ofs, grs->grs_offs + grs->grs_payload_length);

      if ( actual_ofs >= 0 && (grs->grs_offs + grs->grs_payload_length) > actual_ofs ) {
        struct iovec wrreq;

        // Now update the size
        if ( aipf->aipf_personaset_size == 0 )
          aipf->aipf_personaset_size = grs->grs_length;
        else if ( aipf->aipf_personaset_size != grs->grs_length ) {
          fprintf(stderr, "aipf_control: size mismatch when saving personaset\n");
          ret = -1;
        }

        if ( ret >= 0 ) {
          // Reset the timer
          if ( eventloop_cancel_timer(aipf->aipf_el, &aipf->aipf_req_timeout) )
            AIPF_WUNREF(aipf);

          if ( (grs->grs_offs + grs->grs_payload_length) > grs->grs_length )
            grs->grs_payload_length = grs->grs_length - grs->grs_offs;

          wrreq.iov_base = grs->grs_payload + actual_ofs - grs->grs_offs;
          wrreq.iov_len = grs->grs_offs + grs->grs_payload_length - actual_ofs;

          if ( cps_write(pf->pf_cached, &wrreq) < 0 ) {
            fprintf(stderr, "aipf_control: could not write cached persona set\n");
            ret = -1;
          }

          aipf->aipf_offset += grs->grs_payload_length;
          assert(aipf->aipf_offset <= aipf->aipf_personaset_size);

          fprintf(stderr, "aipf_control: Completion %d %d\n", aipf->aipf_offset, aipf->aipf_personaset_size);

          if ( aipf->aipf_offset == aipf->aipf_personaset_size ) {
            cps_rcomplete(pf->pf_cached);
            fprintf(stderr, "aipf_control: Has completed\n");
            has_completed = 1;
            ret = 1;
          } else
            should_request_send = 1;
        }
      } else
        ret = -1;
    } else {
      fprintf(stderr, "aipf_control: tx mismatch\n");
      ret = 0;
    }
    pthread_mutex_unlock(&pf->pf_mutex);

    if ( should_request_send ) {
      stun_random_tx_id(&aipf->aipf_tx_id);
      aipersonasfetcher_send_packet(aipf);
    }

    // If we have completed, mark ourselves complete
    if ( has_completed ) {
      personasfetcher_mark_complete(pf, aipf->aipf_el, 1);
      if ( eventloop_cancel_timer(aipf->aipf_el, &aipf->aipf_req_timeout) )
        AIPF_WUNREF(aipf);
    }

    AIPF_UNREF(aipf);
    return ret;
  default:
    fprintf(stderr, "aipf_control: unknown op %d\n", op);
    return -2;
  }
}

static int aipersonasfetcher_init(struct aipersonasfetcher *aipf,
                                  const unsigned char *hash,
                                  struct cpersonaset *cache_entry,
                                  struct applianceinfo *info) {
  if ( personasfetcher_init(&aipf->aipf_fetcher, hash, cache_entry, aipf_control, aipf_free) < 0 )
    return -1;

  aipf->aipf_el = NULL;
  aipf->aipf_appliance = info;

  aipf->aipf_personaset_size = 0;
  aipf->aipf_offset = 0;

  stun_random_tx_id(&aipf->aipf_tx_id);

  fcspktwriter_init(&aipf->aipf_pkt_writer,
                    &aipf->aipf_fetcher.pf_shared,
                    aipf_write_pkt,
                    OP_AIPF_PKT_WRITTEN,
                    aipersonasfetcher_evtfn);

  timersub_init_default(&aipf->aipf_req_timeout, OP_AIPF_REQ_TIMEOUT, aipersonasfetcher_evtfn);
  aipf->aipf_req_retries = 0;

  return 0;
}

static void aipersonasfetcher_release(struct aipersonasfetcher *aipf) {

  personasfetcher_release(&aipf->aipf_fetcher);
}

static void aipersonasfetcher_start(struct aipersonasfetcher *aipf,
                                    struct eventloop *el) {
  aipf->aipf_el = el;
  aipersonasfetcher_send_packet(aipf);  // Start by sending a request
}

static int aipf_write_pkt(struct fcspktwriter *pw, char *buf, int *sz) {
  struct aipersonasfetcher *aipf = STRUCT_FROM_BASE(struct aipersonasfetcher, aipf_pkt_writer, pw);
  int max_req_sz = *sz, err;

  struct stunmsg *msg = (struct stunmsg *) buf;
  struct stunattr *attr = STUN_FIRSTATTR(msg);

  *sz = 0;
  fprintf(stderr, "aipf_write_pkt: writing packet\n");

  if ( !STUN_IS_VALID(attr, msg, max_req_sz) ) return -1;

  STUN_INIT_MSG(msg, STUN_INTRUSTD_GET_PERSONAS);
  memcpy(&msg->sm_tx_id, &aipf->aipf_tx_id, sizeof(msg->sm_tx_id));
  STUN_INIT_ATTR(attr, STUN_ATTR_INTRUSTD_PERSONAS_HASH, sizeof(aipf->aipf_fetcher.pf_hash));
  if ( !STUN_ATTR_IS_VALID(attr, msg, max_req_sz) ) return -1;
  memcpy((char *) STUN_ATTR_DATA(attr), aipf->aipf_fetcher.pf_hash, sizeof(aipf->aipf_fetcher.pf_hash));

  attr = STUN_NEXTATTR(attr);
  if ( !STUN_IS_VALID(attr, msg, max_req_sz) ) return -1;
  STUN_INIT_ATTR(attr, STUN_ATTR_INTRUSTD_PERSONAS_OFFS, sizeof(aipf->aipf_offset));
  if ( !STUN_ATTR_IS_VALID(attr, msg, max_req_sz) ) return -1;
  *((uint32_t *) STUN_ATTR_DATA(attr)) = htonl(aipf->aipf_offset);

  STUN_FINISH_WITH_FINGERPRINT(attr, msg, max_req_sz, err);
  if ( err == 0 ) {
    *sz = STUN_MSG_LENGTH(msg);
    return 0;
  } else
    return -1;
}

int applianceinfo_receive_persona_response(struct applianceinfo *info,
                                           const struct stunmsg *msg,
                                           int buf_sz) {
  struct getpersonasrsp rsp;
  int i;

  struct stunattr *attr;

  rsp.grs_tx_id = &msg->sm_tx_id;
  rsp.grs_personas_hash = NULL;
  rsp.grs_offs = 0xFFFFFFFF;
  rsp.grs_length = 0xFFFFFFFF;
  rsp.grs_payload_length = 0;
  rsp.grs_payload = NULL;

  // message is too big
  if ( STUN_MSG_LENGTH(msg) > buf_sz ) return -1;

  for ( attr = STUN_FIRSTATTR(msg);
        STUN_IS_VALID(attr, msg, buf_sz);
        attr = STUN_NEXTATTR(attr) ) {
    switch ( STUN_ATTR_NAME(attr) ) {
    case STUN_ATTR_INTRUSTD_PERSONAS_HASH:
      if ( STUN_ATTR_PAYLOAD_SZ(attr) == SHA256_DIGEST_LENGTH )
        rsp.grs_personas_hash = STUN_ATTR_DATA(attr);
      break;
    case STUN_ATTR_INTRUSTD_PERSONAS_OFFS:
      if ( STUN_ATTR_PAYLOAD_SZ(attr) == sizeof(rsp.grs_offs) )
        rsp.grs_offs = ntohl(*((uint32_t *) STUN_ATTR_DATA(attr)));
      break;
    case STUN_ATTR_INTRUSTD_PERSONAS_SIZE:
      if ( STUN_ATTR_PAYLOAD_SZ(attr) == sizeof(rsp.grs_length) )
        rsp.grs_length = ntohl(*((uint32_t *) STUN_ATTR_DATA(attr)));
      break;
    case STUN_ATTR_INTRUSTD_PERSONAS_DATA:
      if ( STUN_ATTR_PAYLOAD_SZ(attr) > 0 ) {
        rsp.grs_payload = STUN_ATTR_DATA(attr);
        rsp.grs_payload_length = STUN_ATTR_PAYLOAD_SZ(attr);
      }
      break;
    case STUN_ATTR_FINGERPRINT:
      break;
    default:
      break;
    }
  }

  if ( !rsp.grs_personas_hash ) {
    fprintf(stderr, "applianceinfo_receive_persona_response: missing personas hash\n");
    return -1;
  }
  if ( rsp.grs_offs == 0xFFFFFFFF ) {
    fprintf(stderr, "applianceinfo_receive_persona_response: missing personas offset\n");
    return -1;
  }
  if ( rsp.grs_length == 0xFFFFFFFF ) {
    fprintf(stderr, "applianceinfo_receive_persona_response: missing personas size\n");
    return -1;
  }
  if ( rsp.grs_payload_length == 0 && rsp.grs_offs != rsp.grs_length ) {
    fprintf(stderr, "applianceinfo_receive_persona_response: missing personas data\n");
    return -1;
  }

  if ( pthread_mutex_lock(&info->ai_mutex) == 0 ) {
    int was_processed = 0;
    for ( i = 0; i < AI_PERSONA_COUNT && info->ai_personas[i]; ++i ) {
      if ( personasfetcher_hash_matches(info->ai_personas[i], rsp.grs_personas_hash) ) {
        if ( info->ai_personas[i]->pf_control(info->ai_personas[i], PF_OP_AIPF_RECEIVE_STUN, &rsp) == 1 ) {
          was_processed = 1;
          break;
        }
      }
    }

    if ( was_processed )
      fprintf(stderr, "applianceinfo_receive_persona_response: processed personas data\n");
    else
      fprintf(stderr, "applianceinfo_receive_persona_response: did not process personas data\n");

    pthread_mutex_unlock(&info->ai_mutex);
    return 0;
  } else
    return -1;
}

X509 *applianceinfo_get_peer_certificate(struct applianceinfo *info) {
  X509 *ret;
  if ( info->ai_appliance_fn(info, AI_OP_GET_CERTIFICATE, &ret) < 0 ) {
    ret = NULL;
  }
  return ret;
}

void applianceinfo_update_client(struct applianceinfo *info, struct flockclientstate *fcs) {
  struct flockclientstate *old_fcs;
  FLOCKCLIENT_REF(fcs);

  SAFE_MUTEX_LOCK(&info->ai_mutex);
  old_fcs = info->ai_fcs;
  if ( old_fcs )
    FLOCKCLIENT_REF(old_fcs);
  info->ai_fcs = fcs;
  pthread_mutex_unlock(&info->ai_mutex);

  if ( old_fcs )
    FLOCKCLIENT_UNREF(old_fcs);
  if ( old_fcs == fcs )
    FLOCKCLIENT_UNREF(fcs);
}
