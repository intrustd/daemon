#include <stdarg.h>
#include <assert.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <uriparser/Uri.h>

#include "local.h"
#include "util.h"
#include "flock.h"
#include "update.h"
#include "token.h"

#define OP_LOCALAPI_RECV_MSG EVT_CTL_CUSTOM
#define OP_LOCALAPI_UPDATE_COMPLETE (EVT_CTL_CUSTOM + 1)
#define OP_LOCALAPI_CONTAINER_CMD_COMPLETE (EVT_CTL_CUSTOM + 2)

#define MAX_PERSONA_LIMIT 10

#define LOCALAPI_SUBSCRIBE(el, api)                                     \
  eventloop_subscribe_fd((el), (api)->la_socket,                        \
                         ((api)->la_busy ? 0 : FD_SUB_READ) |           \
                         (((api)->la_outgoing_sz >= 4 || api->la_is_listing) ? FD_SUB_WRITE : 0), \
                         &(api)->la_socket_sub);

struct localapi {
  struct appstate *la_app_state;

  int la_socket;
  struct fdsub la_socket_sub;

  struct qdevtsub la_update_completion;
  struct fdsub la_container_completion;
  int la_container_sts_fd;

  int la_busy : 1;
  int la_is_listing : 1;
  struct shared **la_listing;
  unsigned int la_listing_offs, la_listing_count;
  uint16_t la_listing_ent;

  struct appupdater *la_current_updater;
  struct fdsub la_container_waiter;

  char la_outgoing[KITE_MAX_LOCAL_MSG_SZ];
  int la_outgoing_sz;
};

static void localsock_hup(struct localapi *api, struct eventloop *el);
static void localsock_handle_message(struct localapi *api, struct eventloop *el,
                                     const char *buf, int buf_sz,
                                     struct msghdr *skmsg);
static int localsock_flush(struct localapi *api, struct eventloop *el);
static void localsock_update_completes(struct localapi *api);
static void localsock_cmd_completes(struct localapi *api, int sts);
static int localsock_respond_simple(struct localapi *api, struct eventloop *el,
                                    uint16_t req, uint16_t code);
static void localsock_free_listing(struct localapi *api);
static int localsock_start_list(struct localapi *api, uint16_t ent, unsigned int count);
static void localsock_do_list(struct localapi *api, struct eventloop *el);

static void localsockfn(struct eventloop *el, int op, void *arg) {
  struct localapi *api;
  struct fdevent *fde;
  struct qdevent *qde;
  int err;

  char buf[KITE_MAX_LOCAL_MSG_SZ], cbuf[128];

  switch ( op ) {
  case OP_LOCALAPI_CONTAINER_CMD_COMPLETE:
    fde = arg;
    api = STRUCT_FROM_BASE(struct localapi, la_container_completion, fde->fde_sub);

    if ( FD_READ_PENDING(fde) ) {
      int sts = 0;

      // Read status
      err = read(api->la_container_sts_fd, &sts, sizeof(sts));
      if ( err < sizeof(sts) )  {
        perror("localsockfn(OP_LOCALAPI_CONTAINER_CMD_COMPLETE): recv");
        localsock_respond_simple(api, el, ntohs(KLM_REQ_SUB | KLM_REQ_ENTITY_CONTAINER), KLE_SYSTEM_ERROR);
      } else {
        localsock_cmd_completes(api, sts);
      }
    } else if ( FD_ERROR_PENDING(fde) ) {
      localsock_respond_simple(api, el, ntohs(KLM_REQ_SUB | KLM_REQ_ENTITY_CONTAINER), KLE_SYSTEM_ERROR);
    }

    api->la_busy = 0;

    close(api->la_container_sts_fd);
    api->la_container_sts_fd = -1;

    LOCALAPI_SUBSCRIBE(el, api);
    break;

  case OP_LOCALAPI_UPDATE_COMPLETE:
    qde = arg;
    api = STRUCT_FROM_BASE(struct localapi, la_update_completion, qde->qde_sub);
    fprintf(stderr, "localapi: update complete\n");
    localsock_update_completes(api);
    break;

  case OP_LOCALAPI_RECV_MSG:
    fde = (struct fdevent *) arg;
    api = STRUCT_FROM_BASE(struct localapi, la_socket_sub, fde->fde_sub);

    if ( FD_WRITE_AVAILABLE(fde) ) {
      err = localsock_flush(api, el);
      if ( err < 0 ) {
        fprintf(stderr, "localapi_flush: failed\n");
        localsock_hup(api, el);
        return;
      }

      if ( api->la_outgoing_sz < 4 && api->la_is_listing ) {
        localsock_do_list(api, el);
      }
    }

    if ( FD_READ_PENDING(fde) && !api->la_busy ) {
      struct iovec iov[1] = {
        { .iov_base = buf,
          .iov_len = sizeof(buf)
        }
      };
      struct msghdr msg = {
        .msg_flags = 0,

        .msg_name = NULL,
        .msg_namelen = 0,

        .msg_iov = iov,
        .msg_iovlen = 1,

        .msg_control = cbuf,
        .msg_controllen = sizeof(cbuf)
      };
      err = recvmsg(api->la_socket, &msg, 0);
      if ( err <= 0 ) {
        if ( err < 0 )
          perror("localsockfn: recv");
        localsock_hup(api, el);
        return;
      }

      localsock_handle_message(api, el, buf, err, &msg);
    }

    LOCALAPI_SUBSCRIBE(el, api);
    break;
  default:
    fprintf(stderr, "localsockfn: Unknown op %d\n", op);
    return;
  }
}

struct localapi *localapi_alloc(struct appstate *as, int sk) {
  int err;
  struct localapi *ret = (struct localapi *) malloc(sizeof(struct localapi));
  if ( !ret ) {
    perror("localapi_alloc: malloc");
    return NULL;
  }

  err = set_socket_nonblocking(sk);
  if ( err < 0 ) {
    perror("localapi_alloc: set_socket_nonblocking");
    goto error;
  }

  ret->la_current_updater = NULL;
  ret->la_app_state = as;
  ret->la_socket = sk;
  ret->la_busy = 0;
  ret->la_is_listing = 0;
  ret->la_listing = NULL;
  ret->la_listing_offs = 0;
  ret->la_listing_count = 0;
  ret->la_listing_ent = 0;
  ret->la_outgoing_sz = 0;
  ret->la_container_sts_fd = -1;
  fdsub_init(&ret->la_socket_sub, &as->as_eventloop, ret->la_socket, OP_LOCALAPI_RECV_MSG, localsockfn);

  qdevtsub_init(&ret->la_update_completion, OP_LOCALAPI_UPDATE_COMPLETE, localsockfn);
  eventloop_subscribe_fd(&as->as_eventloop, ret->la_socket, FD_SUB_READ, &ret->la_socket_sub);

  //  fprintf(stderr, "Opened local connection %p\n", ret);
  return ret;

 error:
  free(ret);
  return NULL;
}

static int localsock_start_list(struct localapi *api, uint16_t ent, unsigned int count) {
  struct shared **new_buf;

  localsock_free_listing(api);

  if ( count > 0 ) {
    new_buf = malloc(sizeof(*api->la_listing) * count);
    if ( !new_buf ) return -1;

    api->la_listing = new_buf;
    memset(new_buf, 0, sizeof(*api->la_listing) * count);
  } else
    api->la_listing = NULL;

  api->la_is_listing = 1;
  api->la_busy = 1;
  api->la_listing_ent = ent;
  api->la_listing_offs = 0;
  api->la_listing_count = count;

  return 0;
}

static void localsock_free_listing(struct localapi *api) {
  if ( api->la_is_listing ) {
    unsigned int i;
    for ( i = api->la_listing_offs; i < api->la_listing_count; ++i ) {
      if ( api->la_listing[i] )
        SHARED_UNREF(api->la_listing[i]);
    }

    free(api->la_listing);
  }
  api->la_is_listing = 0;
  api->la_listing_ent = 0;
  api->la_listing = NULL;
  api->la_listing_offs = api->la_listing_count = 0;
}

static void localsock_hup(struct localapi *api, struct eventloop *el) {
  //fprintf(stderr, "Local connection (%p) closing\n", api);

  if ( api->la_socket ) {
    eventloop_unsubscribe_fd(el, api->la_socket, FD_SUB_ALL, &api->la_socket_sub);
    close(api->la_socket);
  }

  if ( api->la_current_updater )
    APPUPDATER_UNREF(api->la_current_updater);

  if ( api->la_container_sts_fd != -1 ) {
    close(api->la_container_sts_fd);
    api->la_container_sts_fd = -1;
  }

  localsock_free_listing(api);

  free(api);
}

static int localsock_respond(struct localapi *api, struct eventloop *el,
                             const char *buf, int buf_sz) {
  uint32_t *sz;

  if ( (api->la_outgoing_sz + 4 + buf_sz) > sizeof(api->la_outgoing) ) {
    fprintf(stderr, "Dropping local response due to insufficient space\n");
    return -ENOSPC;
  }

  sz = (uint32_t *) (api->la_outgoing + api->la_outgoing_sz);
  *sz = buf_sz;
  memcpy(api->la_outgoing + 4 + api->la_outgoing_sz, buf, buf_sz);
  api->la_outgoing_sz += 4 + buf_sz;

  return 0;
}

// static int localsock_return_error_response(struct localapi *api, struct eventloop *el,
//                                            struct kitelocalmsg *in_response_to, uint16_t err_code) {
//   char buf[KITE_MAX_LOCAL_MSG_SZ];
//   struct kitelocalmsg *msg;
//   struct kitelocalattr *attr;
//   int sz = KLM_SIZE_INIT;
//
//   msg = (struct kitelocalmsg *)buf;
//   attr = KLM_FIRSTATTR(msg, sizeof(buf));
//
//   assert (attr);
//
//   msg->klm_req = htons(KLM_RESPONSE | ntohs(in_response_to->klm_req));
//   msg->klm_req_flags = 0;
//   attr->kla_name = htons(KLA_RESPONSE_CODE);
//   attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));
//   *KLA_DATA_AS(attr, buf, sizeof(buf), uint16_t *) = htons(err_code);
//   KLM_SIZE_ADD_ATTR(sz, attr);
//
//   return localsock_respond(api, el, buf, sz);
// }

static int localsock_return_bad_entity(struct localapi *api, struct eventloop *el,
                                       struct kitelocalmsg *in_response_to, uint16_t entity) {
  char buf[KITE_MAX_LOCAL_MSG_SZ];
  struct kitelocalmsg *msg;
  struct kitelocalattr *attr;
  int sz = KLM_SIZE_INIT;

  msg = (struct kitelocalmsg *)buf;
  attr = KLM_FIRSTATTR(msg, sizeof(buf));

  assert (attr);

  msg->klm_req = htons(KLM_RESPONSE | ntohs(in_response_to->klm_req));
  attr->kla_name = htons(KLA_RESPONSE_CODE);
  attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));
  *KLA_DATA_AS(attr, buf, sizeof(buf), uint16_t *) = htons(KLE_BAD_ENTITY);
  KLM_SIZE_ADD_ATTR(sz, attr);

  attr = KLM_NEXTATTR(msg, attr, sizeof(buf));
  assert(attr);
  attr->kla_name = htons(KLA_ENTITY);
  attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));
  *KLA_DATA_AS(attr, buf, sizeof(buf), uint16_t *) = htons(entity);
  KLM_SIZE_ADD_ATTR(sz, attr);

  return localsock_respond(api, el, buf, sz);
}

static int localsock_return_bad_method(struct localapi *api, struct eventloop *el,
                                       struct kitelocalmsg *in_response_to,
                                       uint16_t entity, uint16_t op) {
  char buf[KITE_MAX_LOCAL_MSG_SZ];
  struct kitelocalmsg *msg;
  struct kitelocalattr *attr;
  int sz = KLM_SIZE_INIT;

  msg = (struct kitelocalmsg *)buf;
  attr = KLM_FIRSTATTR(msg, sizeof(buf));

  assert (attr);

  msg->klm_req = htons(KLM_RESPONSE | ntohs(in_response_to->klm_req));
  attr->kla_name = htons(KLA_RESPONSE_CODE);
  attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));
  *KLA_DATA_AS(attr, buf, sizeof(buf), uint16_t *) = htons(KLE_BAD_OP);
  KLM_SIZE_ADD_ATTR(sz, attr);

  attr = KLM_NEXTATTR(msg, attr, sizeof(buf));
  assert(attr);
  attr->kla_name = htons(KLA_ENTITY);
  attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));
  *KLA_DATA_AS(attr, buf, sizeof(buf), uint16_t *) = htons(entity);
  KLM_SIZE_ADD_ATTR(sz, attr);

  attr = KLM_NEXTATTR(msg, attr, sizeof(buf));
  assert(attr);
  attr->kla_name = htons(KLA_OPERATION);
  attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));
  *KLA_DATA_AS(attr, buf, sizeof(buf), uint16_t *) = htons(op);
  KLM_SIZE_ADD_ATTR(sz, attr);


  return localsock_respond(api, el, buf, sz);
}

static int localsock_return_missing_attrs(struct localapi *api, struct eventloop *el,
                                          struct kitelocalmsg *in_response_to,
                                          ...) {
  va_list args;

  char buf[KITE_MAX_LOCAL_MSG_SZ];
  struct kitelocalmsg *msg = (struct kitelocalmsg *)buf;
  struct kitelocalattr *attr;
  int sz = KLM_SIZE_INIT;
  uint16_t rsp = KLE_MISSING_ATTRIBUTES;

  msg->klm_req = htons(KLM_RESPONSE | ntohs(in_response_to->klm_req));
  msg->klm_req_flags = 0;

  attr = KLM_FIRSTATTR(msg, sizeof(buf));
  attr->kla_name = ntohs(KLA_RESPONSE_CODE);
  attr->kla_length = ntohs(KLA_SIZE(sizeof(rsp)));
  memcpy(KLA_DATA_UNSAFE(attr, uint16_t *), &rsp, sizeof(rsp));
  KLM_SIZE_ADD_ATTR(sz, attr);

  va_start(args, in_response_to);
  while ( 1 ) {
    int mattrn = va_arg(args, int);
    uint16_t mattr;

    if ( mattrn < 0 ) break;

    mattr = mattrn;

    attr = KLM_NEXTATTR(msg, attr, sizeof(buf));
    if ( !attr ) goto done;

    attr->kla_name = ntohs(KLA_ATTRIBUTE);
    attr->kla_length = ntohs(KLA_SIZE(sizeof(mattr)));
    if ( !(KLA_DATA(attr, msg, sizeof(buf))) ) goto done;
    memcpy(KLA_DATA_UNSAFE(attr, uint16_t *), &mattr, sizeof(mattr));
    KLM_SIZE_ADD_ATTR(sz, attr);
  }


 done:
  va_end(args);
  return localsock_respond(api, el, buf, sz);
}

static int localsock_respond_simple(struct localapi *api, struct eventloop *el,
                                    uint16_t req, uint16_t code) {
  char buf[KITE_MAX_LOCAL_MSG_SZ];
  struct kitelocalmsg *msg;
  struct kitelocalattr *attr;
  int sz = KLM_SIZE_INIT;

  msg = (struct kitelocalmsg *)buf;
  attr = KLM_FIRSTATTR(msg, sizeof(buf));

  assert (attr);

  msg->klm_req = htons(KLM_RESPONSE | req);
  attr->kla_name = htons(KLA_RESPONSE_CODE);
  attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));
  *KLA_DATA_AS(attr, buf, sizeof(buf), uint16_t *) = htons(code);
  KLM_SIZE_ADD_ATTR(sz, attr);

  return localsock_respond(api, el, buf, sz);
}

static int localsock_return_simple(struct localapi *api, struct eventloop *el,
                                   struct kitelocalmsg *in_response_to,
                                   uint16_t code) {
  return localsock_respond_simple(api, el, ntohs(in_response_to->klm_req), code);
}

static int localsock_return_not_found(struct localapi *api, struct eventloop *el,
                                      struct kitelocalmsg *in_response_to) {
  return localsock_return_simple(api, el, in_response_to, KLE_NOT_FOUND);
}

static int localsock_return_not_allowed(struct localapi *api, struct eventloop *el,
                                      struct kitelocalmsg *in_response_to) {
  return localsock_return_simple(api, el, in_response_to, KLE_NOT_ALLOWED);
}

// static int localsock_return_not_implemented(struct localapi *api, struct eventloop *el,
//                                             struct kitelocalmsg *in_response_to) {
//   return localsock_return_simple(api, el, in_response_to, KLE_NOT_IMPLEMENTED);
// }

static int localsock_return_internal_error(struct localapi *api, struct eventloop *el,
                                           struct kitelocalmsg *in_response_to) {
  return localsock_return_simple(api, el, in_response_to, KLE_SYSTEM_ERROR);
}

static void localsock_respond_persona(struct localapi *api, struct eventloop *el,
                                      struct kitelocalmsg *in_response_to,
                                      const char *display_name,
                                      uint32_t p_flags) {
  char ret_buf[KITE_MAX_LOCAL_MSG_SZ];
  struct kitelocalmsg *rsp = (struct kitelocalmsg *) ret_buf;
  struct kitelocalattr *attr;
  int rspsz = KLM_SIZE_INIT;

  rsp->klm_req = htons(KLM_RESPONSE | ntohs(in_response_to->klm_req));
  rsp->klm_req_flags = 0;

  attr = KLM_FIRSTATTR(rsp, sizeof(ret_buf));
  assert(attr);

  attr->kla_name = htons(KLA_RESPONSE_CODE);
  attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));
  *(KLA_DATA_UNSAFE(attr, uint16_t *)) = htons(KLE_SUCCESS);
  KLM_SIZE_ADD_ATTR(rspsz, attr);

  attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
  assert(attr);
  attr->kla_name = htons(KLA_PERSONA_DISPLAYNM);
  attr->kla_length = htons(KLA_SIZE(strlen(display_name)));
  memcpy(KLA_DATA_UNSAFE(attr, char *), display_name, strlen(display_name));
  KLM_SIZE_ADD_ATTR(rspsz, attr);

  if ( p_flags ) {
    uint32_t flags[2] = { ntohl(p_flags), 0 };

    attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
    assert(attr);
    attr->kla_name = htons(KLA_PERSONA_FLAGS);
    attr->kla_length = htons(KLA_SIZE(sizeof(flags)));

    memcpy(KLA_DATA_UNSAFE(attr, void *), flags, sizeof(flags));
    KLM_SIZE_ADD_ATTR(rspsz, attr);
  }

  localsock_respond(api, el, ret_buf, rspsz);
  return;
}

static void localsock_get_persona(struct localapi *api, struct eventloop *el,
                                  struct kitelocalmsg *msg, int msgsz) {
  struct kitelocalattr *attr;

  int has_persona_id = 0;
  char persona_id[PERSONA_ID_LENGTH];
  struct persona *p;

  for ( attr = KLM_FIRSTATTR(msg, msgsz); attr; attr = KLM_NEXTATTR(msg, attr, msgsz) ) {
    switch ( KLA_NAME(attr) ) {
    case KLA_PERSONA_ID:
      if ( KLA_PAYLOAD_SIZE(attr) == PERSONA_ID_LENGTH ) {
        has_persona_id = 1;
        memcpy(persona_id, KLA_DATA_UNSAFE(attr, void *), PERSONA_ID_LENGTH);
      } else {
        localsock_return_bad_method(api, el, msg, KLM_REQ_ENTITY(msg), KLM_REQ_OP(msg));
        return;
      }
      break;
    default:
      localsock_return_bad_method(api, el, msg, KLM_REQ_ENTITY(msg), KLM_REQ_OP(msg));
      return;
    }
  }

  if ( !has_persona_id ) {
    unsigned int p_count;
    struct persona *cur, *tmp;

    SAFE_RWLOCK_RDLOCK(&api->la_app_state->as_personas_mutex);
    p_count = HASH_CNT(p_hh, api->la_app_state->as_personas);
    if ( localsock_start_list(api, KLM_REQ_ENTITY_PERSONA, p_count) == 0 ) {
      unsigned int i = 0;
      HASH_ITER(p_hh, api->la_app_state->as_personas, cur, tmp) {
        PERSONA_REF(cur);
        api->la_listing[i] = &cur->p_shared;
        i++;
      }
    } else
      localsock_return_internal_error(api, el, msg);
    pthread_rwlock_unlock(&api->la_app_state->as_personas_mutex);

    return;
  }

  // Look up persona
  if ( appstate_lookup_persona(api->la_app_state, persona_id, &p) < 0 ) {
    localsock_return_not_found(api, el, msg);
    return;
  }
  if ( !p ) {
    localsock_return_not_found(api, el, msg);
    return;
  }

  if ( pthread_mutex_lock(&p->p_mutex) == 0 ) {
    localsock_respond_persona(api, el, msg,
                              p->p_display_name,
                              p->p_flags);
    pthread_mutex_unlock(&p->p_mutex);
    PERSONA_UNREF(p);
  } else
    localsock_return_internal_error(api, el, msg);
}

static void localsock_create_persona(struct localapi *api, struct eventloop *el,
                                     struct kitelocalmsg *msg, int msgsz) {
  char ret_buf[KITE_MAX_LOCAL_MSG_SZ];

  struct kitelocalmsg *rsp = (struct kitelocalmsg *) ret_buf;
  struct kitelocalattr *attr;

  struct persona *persona;

  char *display_name = NULL, *password = NULL;
  int display_name_sz = 0, password_sz = 0;
  uint32_t p_flags = 0;

  int rspsz = KLM_SIZE_INIT;

  rsp->klm_req = htons(KLM_RESPONSE | htons(msg->klm_req));
  rsp->klm_req_flags = 0;

  attr = KLM_FIRSTATTR(rsp, sizeof(ret_buf));
  assert(attr);

  attr->kla_name = htons(KLA_RESPONSE_CODE);
  attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));

  for ( attr = KLM_FIRSTATTR(msg, msgsz); attr; attr = KLM_NEXTATTR(msg, attr, msgsz) ) {
    switch ( KLA_NAME(attr) ) {
    case KLA_PERSONA_DISPLAYNM:
      display_name = KLA_DATA_AS(attr, msg, msgsz, char *);
      display_name_sz = KLA_PAYLOAD_SIZE(attr);
      break;
    case KLA_PERSONA_PASSWORD:
      password = KLA_DATA_AS(attr, msg, msgsz, char *);
      password_sz = KLA_PAYLOAD_SIZE(attr);
      break;
    case KLA_PERSONA_FLAGS:
      if ( KLA_PAYLOAD_SIZE(attr) == sizeof(uint32_t) * 2 ) {
        uint32_t flags[2];
        memcpy(flags, KLA_DATA_UNSAFE(attr, uint64_t *), sizeof(flags));

        p_flags |= ntohl(flags[0]);
        p_flags &= ~ntohl(flags[1]);
      }
      break;
    default:
      goto bad_request;
    }
  }
  if ( !display_name || !password )
    goto bad_request;

  if ( appstate_create_persona(api->la_app_state, display_name, display_name_sz,
                               password, password_sz, p_flags, &persona) < 0 ) {
    goto bad_request;
  }

  assert(persona);

  attr = KLM_FIRSTATTR(rsp, sizeof(ret_buf));
  assert(attr);
  *(KLA_DATA_UNSAFE(attr, uint16_t *)) = htons(KLE_SUCCESS);
  KLM_SIZE_ADD_ATTR(rspsz, attr);

  attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
  assert(attr);
  attr->kla_name = htons(KLA_PERSONA_ID);
  attr->kla_length = htons(KLA_SIZE(PERSONA_ID_LENGTH));
  memcpy(KLA_DATA_UNSAFE(attr, char *), persona->p_persona_id, PERSONA_ID_LENGTH);
  KLM_SIZE_ADD_ATTR(rspsz, attr);

  localsock_respond(api, el, ret_buf, rspsz);

  PERSONA_UNREF(persona);

  return;

 bad_request:
  localsock_return_bad_method(api, el, msg, KLM_REQ_ENTITY(msg), KLM_REQ_OP(msg));
}

static void localsock_get_system(struct localapi *api, struct eventloop *el,
                                 struct kitelocalmsg *msg, int msgsz) {
  char ret_buf[KITE_MAX_LOCAL_MSG_SZ];
  struct kitelocalmsg *rsp = (struct kitelocalmsg *)ret_buf;
  struct kitelocalattr *attr;
  int rspsz = KLM_SIZE_INIT;

  const char *system_type = api->la_app_state->as_system;

  msg->klm_req = htons(KLM_RESPONSE | ntohs(msg->klm_req));
  msg->klm_req_flags = 0;

  attr = KLM_FIRSTATTR(rsp, sizeof(ret_buf));
  assert(attr);

  attr->kla_name = htons(KLA_RESPONSE_CODE);
  attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));
  *(KLA_DATA_UNSAFE(attr, uint16_t *)) = htons(KLE_SUCCESS);
  KLM_SIZE_ADD_ATTR(rspsz, attr);

  attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
  assert(attr);
  attr->kla_name = htons(KLA_SYSTEM_TYPE);
  attr->kla_length = htons(KLA_SIZE(strlen(system_type)));
  if ( !KLA_DATA(attr, rsp, sizeof(ret_buf)) ) {
    localsock_respond_simple(api, el, msg->klm_req, KLE_SYSTEM_ERROR);
    return;
  }
  memcpy(KLA_DATA_UNSAFE(attr, void *), system_type, strlen(system_type));
  KLM_SIZE_ADD_ATTR(rspsz, attr);

  localsock_respond(api, el, ret_buf, rspsz);
}

static void localsock_crud_system(struct localapi *api, struct eventloop *el,
                                  struct kitelocalmsg *msg, int msgsz) {
  switch ( KLM_REQ_OP(msg) ) {
  case KLM_REQ_GET:
    localsock_get_system(api, el, msg, msgsz);
    break;

  default:
    localsock_return_bad_method(api, el, msg, KLM_REQ_ENTITY(msg), KLM_REQ_OP(msg));
    break;
  }
}

static void localsock_crud_persona(struct localapi *api, struct eventloop *el,
                                   struct kitelocalmsg *msg, int msgsz) {
  switch ( KLM_REQ_OP(msg) ) {
  case KLM_REQ_GET:
    localsock_get_persona(api, el, msg, msgsz);
    break;

  case KLM_REQ_CREATE:
    localsock_create_persona(api, el, msg, msgsz);
    break;

  default:
    localsock_return_bad_method(api, el, msg, KLM_REQ_ENTITY(msg), KLM_REQ_OP(msg));
    break;
  }
}

static void localsock_crud_flock(struct localapi *api, struct eventloop *el,
                                 struct kitelocalmsg *msg, int msgsz) {
  char ret_buf[KITE_MAX_LOCAL_MSG_SZ];

  struct kitelocalmsg *rsp = (struct kitelocalmsg *) ret_buf;
  struct kitelocalattr *attr;
  struct flock flock;
  struct flock *current_flock, *tmp_flock;
  int err, rspsz = KLM_SIZE_INIT;
  int found_uri = 0, flock_count, i;

  UriParserStateA flock_uri_parser;
  UriUriA flock_uri;
  flock_uri_parser.uri = &flock_uri;

  rsp->klm_req = htons(KLM_RESPONSE | htons(msg->klm_req));
  rsp->klm_req_flags = 0;
  attr = KLM_FIRSTATTR(rsp, sizeof(ret_buf));
  assert(attr);

  attr->kla_name = htons(KLA_RESPONSE_CODE);
  attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));

  switch ( KLM_REQ_OP(msg) ) {
  case KLM_REQ_CREATE:
    flock_clear(&flock);

    for ( attr = KLM_FIRSTATTR(msg, msgsz); attr; attr = KLM_NEXTATTR(msg, attr, msgsz) ) {
      switch ( KLA_NAME(attr) ) {
      case KLA_FLOCK_URL:
        if ( uriParseUriExA(&flock_uri_parser, KLA_DATA_UNSAFE(attr, char *),
                            KLA_DATA_UNSAFE(attr, char *) + KLA_PAYLOAD_SIZE(attr))
             != URI_SUCCESS ) {
          attr = KLM_FIRSTATTR(rsp, sizeof(ret_buf));
          *(KLA_DATA_UNSAFE(attr, uint16_t *)) = htons(KLE_INVALID_URL);
          KLM_SIZE_ADD_ATTR(rspsz, attr);
          localsock_respond(api, el, ret_buf, rspsz);
          return;
        }

        if ( flock_assign_uri(&flock, &flock_uri) != 0 ) {
          fprintf(stderr, "Could not assign flock URI\n");
          attr = KLM_FIRSTATTR(rsp, sizeof(ret_buf));
          *(KLA_DATA_UNSAFE(attr, uint16_t *)) = htons(KLE_INVALID_URL);
          KLM_SIZE_ADD_ATTR(rspsz, attr);
          localsock_respond(api, el, ret_buf, rspsz);
          return;
        }

        found_uri = 1;
        break;
      default: break;
      }
    }

    attr = KLM_FIRSTATTR(rsp, sizeof(ret_buf));
    if ( !found_uri ) {
      *(KLA_DATA_UNSAFE(attr, uint16_t *)) = htons(KLE_MISSING_ATTRIBUTES);
      KLM_SIZE_ADD_ATTR(rspsz, attr);

      if ( !found_uri ) {
        attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
        attr->kla_name = htons(KLA_REQUEST_ATTRIBUTE);
        attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));
        *(KLA_DATA_UNSAFE(attr, uint16_t *)) = htons(KLA_FLOCK_URL);
        KLM_SIZE_ADD_ATTR(rspsz, attr);
      }

      flock_release(&flock);

      if ( found_uri ) {
        uriFreeUriMembersA(&flock_uri);
      }

      localsock_respond(api, el, ret_buf, rspsz);
      return;
    } else {
      err = appstate_create_flock(api->la_app_state, &flock, 0);
      if ( err < 0 ) {
        *(KLA_DATA_UNSAFE(attr, uint16_t *)) = htons(KLE_SYSTEM_ERROR);
        KLM_SIZE_ADD_ATTR(rspsz, attr);

        attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
        attr->kla_name = htons(KLA_SYSTEM_ERROR);
        attr->kla_length = htons(KLA_SIZE(sizeof(uint32_t)));
        *(KLA_DATA_UNSAFE(attr, uint32_t *)) = htonl(errno);
        KLM_SIZE_ADD_ATTR(rspsz, attr);

        localsock_respond(api, el, ret_buf, rspsz);
        return;
      } else {
        *(KLA_DATA_UNSAFE(attr, uint16_t *)) = htons(KLE_SUCCESS);
        KLM_SIZE_ADD_ATTR(rspsz, attr);
        localsock_respond(api, el, ret_buf, rspsz);
        return;
      }
    }
    break;

  case KLM_REQ_GET:
    SAFE_RWLOCK_RDLOCK(&api->la_app_state->as_flocks_mutex);
    flock_count = HASH_CNT(f_hh, api->la_app_state->as_flocks);
    i = 0;
    HASH_ITER(f_hh, api->la_app_state->as_flocks, current_flock, tmp_flock) {
      rspsz = KLM_SIZE_INIT;

      rsp->klm_req_flags = KLM_RETURN_MULTIPLE;
      if ( ++i == flock_count ) {
        rsp->klm_req_flags |= KLM_IS_LAST;
      }
      rsp->klm_req_flags = htons(rsp->klm_req_flags);

      attr = KLM_FIRSTATTR(rsp, sizeof(ret_buf));
      assert(attr);
      attr->kla_name = htons(KLA_RESPONSE_CODE);
      attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));
      *(KLA_DATA_AS(attr, rsp, sizeof(ret_buf), uint16_t*)) = htons(KLE_SUCCESS);
      KLM_SIZE_ADD_ATTR(rspsz, attr);

      attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
      assert(attr);
      attr->kla_name = htons(KLA_FLOCK_URL);
      attr->kla_length = htons(KLA_SIZE(strlen(current_flock->f_uri_str)));
      memcpy(KLA_DATA_UNSAFE(attr, char *), current_flock->f_uri_str, KLA_PAYLOAD_SIZE(attr));
      KLM_SIZE_ADD_ATTR(rspsz, attr);

      attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
      assert(attr);
      attr->kla_name = htons(KLA_FLOCK_STATUS);
      attr->kla_length = htons(KLA_SIZE(sizeof(uint32_t)));
      *(KLA_DATA_AS(attr, rsp, sizeof(ret_buf), uint32_t *)) = htonl(current_flock->f_flags);
      KLM_SIZE_ADD_ATTR(rspsz, attr);

      if ( current_flock->f_flags & FLOCK_FLAG_VALIDATE_CERT ) {
        attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
        assert(attr);
        attr->kla_name = htons(KLA_FLOCK_SIGNATURE);
        attr->kla_length = htons(KLA_SIZE(sizeof(current_flock->f_expected_digest)));
        memcpy(KLA_DATA_UNSAFE(attr, unsigned char *), current_flock->f_expected_digest, sizeof(current_flock->f_expected_digest));
        KLM_SIZE_ADD_ATTR(rspsz, attr);
      }

      err = localsock_respond(api, el, ret_buf, rspsz);
      if ( err < 0 ) {
        if ( err == -ENOSPC ) {
          fprintf(stderr, "Not listing all flocks because there is no space in the output buffer\n");
        } else
          perror("localsock_respond");
        break;
      }

      fprintf(stderr, "returning more flocks\n");

      if ( !(ntohs(msg->klm_req_flags) & KLM_RETURN_MULTIPLE) ) break;
    }
    pthread_rwlock_unlock(&api->la_app_state->as_flocks_mutex);
    break;

  default:
    *(KLA_DATA_UNSAFE(attr, uint16_t *)) = htons(KLE_BAD_OP);
    KLM_SIZE_ADD_ATTR(rspsz, attr);

    attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
    assert(attr);
    attr->kla_name = htons(KLA_ENTITY);
    attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));
    *(KLA_DATA_UNSAFE(attr, uint16_t *)) = htons(KLM_REQ_ENTITY(msg));
    KLM_SIZE_ADD_ATTR(rspsz, attr);

    attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
    assert(attr);
    attr->kla_name = htons(KLA_OPERATION);
    attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));
    *(KLA_DATA_UNSAFE(attr, uint16_t *)) = htons(KLM_REQ_OP(msg));
    KLM_SIZE_ADD_ATTR(rspsz, attr);

    localsock_respond(api, el, ret_buf, rspsz);
  }
}

static void localsock_get_app(struct localapi *api, struct eventloop *el,
                              struct kitelocalmsg *msg, int msgsz) {
  char ret_buf[KITE_MAX_LOCAL_MSG_SZ];

  struct kitelocalmsg *rsp = (struct kitelocalmsg *) ret_buf;
  struct kitelocalattr *attr;

  const char *app_uri = NULL;
  size_t app_uri_sz = 0;
  struct app *app;

  int rspsz = KLM_SIZE_INIT, found_app_url = 0;

  for ( attr = KLM_FIRSTATTR(msg, msgsz); attr; attr = KLM_NEXTATTR(msg, attr, msgsz) ) {
    switch ( KLA_NAME(attr) ) {
    case KLA_APP_URL:
      if ( found_app_url ) {
        localsock_return_bad_method(api, el, msg, KLM_REQ_ENTITY(msg), KLM_REQ_OP(msg));
        return;
      } else {
        found_app_url = 1;
        app_uri_sz = KLA_PAYLOAD_SIZE(attr);
        app_uri = KLA_DATA_UNSAFE(attr, char *);
      }
      break;
    default:
      break;
    }
  }

  if ( !found_app_url ) {
    localsock_return_bad_method(api, el, msg, KLM_REQ_ENTITY(msg), KLM_REQ_OP(msg));
    return;
  }

  fprintf(stderr, "Looking up %.*s\n", (int)app_uri_sz, app_uri);
  app = appstate_get_app_by_url_ex(api->la_app_state, app_uri, app_uri_sz);
  if ( !app ) {
    fprintf(stderr, "App not found\n");
    localsock_return_not_found(api, el, msg);
  } else {
    struct appmanifest *mf;
    int is_signed = 0;
    char mf_str[sizeof(mf->am_digest) * 2 + 1];

    if ( pthread_mutex_lock(&app->app_mutex) == 0 ) {
      mf = app->app_current_manifest;
      is_signed = !!(app->app_flags & APP_FLAG_SIGNED);
      pthread_mutex_unlock(&app->app_mutex);
    } else {
      localsock_return_internal_error(api, el, msg);
      return;
    }

    rsp->klm_req = htons(KLM_RESPONSE | htons(msg->klm_req));
    rsp->klm_req_flags = 0;

    attr = KLM_FIRSTATTR(rsp, sizeof(ret_buf));
    assert(attr);

    attr->kla_name = htons(KLA_RESPONSE_CODE);
    attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));
    *(KLA_DATA_UNSAFE(attr, uint16_t *)) = htons(KLE_SUCCESS);
    KLM_SIZE_ADD_ATTR(rspsz, attr);

    attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
    attr->kla_name = htons(KLA_MANIFEST_NAME);
    attr->kla_length = htons(KLA_SIZE(2 * sizeof(mf->am_digest)));
    hex_digest_str(mf->am_digest, mf_str, sizeof(mf->am_digest));
    memcpy(KLA_DATA_UNSAFE(attr, char *), mf_str, sizeof(mf->am_digest) * 2);
    KLM_SIZE_ADD_ATTR(rspsz, attr);

    if ( is_signed ) {
      attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
      attr->kla_name = htons(KLA_MANIFEST_NAME);
      attr->kla_length = htons(KLA_SIZE(0));
      KLM_SIZE_ADD_ATTR(rspsz, attr);
    }

    localsock_respond(api, el, ret_buf, rspsz);
  }
}

static void localsock_create_app(struct localapi *api, struct eventloop *el,
                                 struct kitelocalmsg *msg, int msgsz,
                                 int *fds, int nfds) {
  char ret_buf[KITE_MAX_LOCAL_MSG_SZ];

  struct kitelocalmsg *rsp = (struct kitelocalmsg *) ret_buf;
  struct kitelocalattr *attr;

  const char *app_uri, *sign_uri = NULL;
  size_t app_uri_sz, sign_uri_sz = 0;

  int rspsz = KLM_SIZE_INIT, found_app_manifest = 0, do_force = 0, progress = -1, infer_app_sign = 1;

  rsp->klm_req = htons(KLM_RESPONSE | htons(msg->klm_req));
  rsp->klm_req_flags = 0;

  attr = KLM_FIRSTATTR(rsp, sizeof(ret_buf));
  assert(attr);

  attr->kla_name = htons(KLA_RESPONSE_CODE);
  attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));

  for ( attr = KLM_FIRSTATTR(msg, msgsz); attr; attr = KLM_NEXTATTR(msg, attr, msgsz) ) {
    switch ( KLA_NAME(attr) ) {
    case KLA_APP_MANIFEST_URL:
      app_uri = KLA_DATA_UNSAFE(attr, char *);
      app_uri_sz = KLA_PAYLOAD_SIZE(attr);
      found_app_manifest = 1;
      break;

    case KLA_APP_SIGNATURE_URL:
      sign_uri = KLA_DATA_UNSAFE(attr, char *);
      sign_uri_sz = KLA_PAYLOAD_SIZE(attr);
      infer_app_sign = 0;

      if ( sign_uri_sz == 0 )
        sign_uri = NULL;
      break;

    case KLA_FORCE:
      do_force = 1;
      break;

    case KLA_STDOUT:
      if ( KLA_PAYLOAD_SIZE(attr) == sizeof(uint8_t) ) {
        uint8_t fdix;
        memcpy(&fdix, KLA_DATA_UNSAFE(attr, void*), sizeof(fdix));
        if ( fdix < nfds ) {
          progress = fds[fdix];
        }
      }
      break;

    default: break;
    }
  }

  attr = KLM_FIRSTATTR(rsp, sizeof(ret_buf));
  assert(attr);
  if ( !found_app_manifest ) {
    *(KLA_DATA_UNSAFE(attr, uint16_t *)) = htons(KLE_MISSING_ATTRIBUTES);
    KLM_SIZE_ADD_ATTR(rspsz, attr);

    attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
    attr->kla_name = htons(KLA_REQUEST_ATTRIBUTE);
    attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));
    *(KLA_DATA_UNSAFE(attr, uint16_t *)) = htons(KLA_APP_MANIFEST_URL);
    KLM_SIZE_ADD_ATTR(rspsz, attr);

    localsock_respond(api, el, ret_buf, rspsz);

    return;
  } else {
    int progress_fd = -1;
    struct appupdater *u;

    if ( infer_app_sign && !sign_uri ) {
      sign_uri_sz = app_uri_sz + 5;
      sign_uri = malloc(sign_uri_sz + 1);
      if ( !sign_uri ) {
        fprintf(stderr, "No space for signature url\n");
        localsock_return_internal_error(api, el, msg);
        return;
      }

      snprintf((char *)sign_uri, sign_uri_sz + 1, "%.*s.sign", (int)app_uri_sz, app_uri);
    }

    if ( progress > 0 ) {
      progress_fd = dup(progress);
      if ( progress_fd < 0 )
        perror("dup(progress)");
    }

    u = appstate_queue_update_ex(api->la_app_state,
                                 app_uri, app_uri_sz,
                                 sign_uri, sign_uri_sz,
                                 AU_UPDATE_REASON_MANUAL,
                                 progress_fd, NULL);
    if ( !u ) {
      *(KLA_DATA_UNSAFE(attr, uint16_t *)) = htons(KLE_SYSTEM_ERROR);
      KLM_SIZE_ADD_ATTR(rspsz, attr);
      localsock_respond(api, el, ret_buf, rspsz);
      return;
    }

    appupdater_request_event(u, &api->la_update_completion);
    if ( do_force ) appupdater_force(u);
    appupdater_start(u);
    api->la_busy = 1;
    api->la_current_updater = u;
  }
}

static void localsock_crud_app(struct localapi *api, struct eventloop *el,
                               struct kitelocalmsg *msg, int msgsz,
                               int *fds, int nfds) {

  switch ( KLM_REQ_OP(msg) ) {
  case KLM_REQ_CREATE:
    localsock_create_app(api, el, msg, msgsz, fds, nfds);
    break;

  case KLM_REQ_GET:
    localsock_get_app(api, el, msg, msgsz);
    break;

  default:
    localsock_return_bad_method(api, el, msg, KLM_REQ_ENTITY(msg), KLM_REQ_OP(msg));
  }
  return;
}

static void localsock_get_container(struct localapi *api, struct eventloop *el,
                                    struct kitelocalmsg *msg, int msgsz) {
  struct kitelocalattr *attr;

  struct in_addr addr;
  addr.s_addr = 0;

  for ( attr = KLM_FIRSTATTR(msg, msgsz); attr; attr = KLM_NEXTATTR(msg, attr, msgsz) ) {
    switch ( KLA_NAME(attr) ) {
    case KLA_ADDR:
      if ( KLA_PAYLOAD_SIZE(attr) == sizeof(addr) ) {
        memcpy(&addr.s_addr, KLA_DATA_UNSAFE(attr, void *), sizeof(addr.s_addr));
      }
      break;

    default:break;
    }
  }

  if ( addr.s_addr == 0 ){
    localsock_return_missing_attrs(api, el, msg, KLM_REQ_ENTITY(msg), KLM_REQ_OP(msg),
                                   KLA_ADDR, -1);
  } else {
    int err;
    struct arpdesc desc;

    err = bridge_describe_arp(&api->la_app_state->as_bridge, &addr, &desc, sizeof(desc));
    if ( err == 0 )
      localsock_return_not_found(api, el, msg);
    else if ( err < 0 )
      localsock_return_internal_error(api, el, msg);
    else {
      char ret_buf[KITE_MAX_LOCAL_MSG_SZ];
      uint16_t code;

      struct kitelocalmsg *rsp = (struct kitelocalmsg *) ret_buf;
      int rspsz = KLM_SIZE_INIT;

      const char *hash_sn;
      int hash_type_nid, hash_len, hash_name_len;

      attr = KLM_FIRSTATTR(rsp, sizeof(ret_buf));

      rsp->klm_req = htons(KLM_RESPONSE | ntohs(msg->klm_req));
      rsp->klm_req_flags = 0;
      attr->kla_name = htons(KLA_RESPONSE_CODE);
      attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));
      code = htons(KLE_SUCCESS);
      memcpy(KLA_DATA_UNSAFE(attr, void *), &code, sizeof(code));
      KLM_SIZE_ADD_ATTR(rspsz, attr);

      switch ( desc.ad_container_type ) {
      case ARP_DESC_PERSONA:
        attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
        assert(attr);
        attr->kla_name = htons(KLA_CONTAINER_TYPE);
        attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));
        code = htons(desc.ad_container_type);
        memcpy(KLA_DATA_UNSAFE(attr, void *), &code, sizeof(code));
        KLM_SIZE_ADD_ATTR(rspsz, attr);

        attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
        assert(attr);
        attr->kla_name = htons(KLA_PERSONA_ID);
        attr->kla_length = htons(KLA_SIZE(PERSONA_ID_LENGTH));
        memcpy(KLA_DATA_UNSAFE(attr, void *), desc.ad_persona.ad_persona_id,
               PERSONA_ID_LENGTH);
        KLM_SIZE_ADD_ATTR(rspsz, attr);

        if ( pthread_mutex_lock(&desc.ad_persona.ad_pconn->pc_mutex) == 0 ) {
          struct pconntoken *cur_tok, *tmp_tok;

          attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
          assert(attr);
          attr->kla_name = htons(KLA_PCONN_ID);
          attr->kla_length = htons(KLA_SIZE(sizeof(uint64_t)));
          memcpy(KLA_DATA_UNSAFE(attr, void *), &desc.ad_persona.ad_pconn->pc_conn_id,
                 sizeof(uint64_t));
          KLM_SIZE_ADD_ATTR(rspsz, attr);

          // Authenticated or not
          if ( desc.ad_persona.ad_pconn->pc_is_logged_in ) {
            attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
            assert(attr);
            attr->kla_name = htons(KLA_SIGNED);
            attr->kla_length = htons(KLA_SIZE(0));
            KLM_SIZE_ADD_ATTR(rspsz, attr);
          }

          if ( desc.ad_persona.ad_pconn->pc_is_guest ) {
            attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
            assert(attr);
            attr->kla_name = htons(KLA_GUEST);
            attr->kla_length = htons(KLA_SIZE(0));
            KLM_SIZE_ADD_ATTR(rspsz, attr);
          }

          // Site ID
          hash_type_nid = EVP_MD_type(desc.ad_persona.ad_pconn->pc_remote_cert_fingerprint_digest);
          assert(hash_type_nid != NID_undef);

          hash_sn = OBJ_nid2sn(hash_type_nid);
          assert(hash_sn);

          hash_name_len = strlen(hash_sn) + 1;
          hash_len = EVP_MD_size(desc.ad_persona.ad_pconn->pc_remote_cert_fingerprint_digest);

          attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
          assert(attr);
          attr->kla_name = htons(KLA_SITE_ID);
          attr->kla_length = htons(KLA_SIZE(hash_name_len + 2 * hash_len));
          assert(KLA_DATA(attr, ret_buf, sizeof(ret_buf)));
          memcpy(KLA_DATA_UNSAFE(attr, char *), hash_sn, hash_name_len - 1);
          (KLA_DATA_UNSAFE(attr, char *))[hash_name_len] = ':';
          hex_digest_str((unsigned char *) desc.ad_persona.ad_pconn->pc_remote_cert_fingerprint,
                         KLA_DATA_UNSAFE(attr, char *) + hash_name_len,
                         hash_len);
          memcpy(KLA_DATA_UNSAFE(attr, char *) + hash_name_len - 1,
                 KLA_DATA_UNSAFE(attr, char *) + hash_name_len,
                 2 * hash_len);
          (KLA_DATA_UNSAFE(attr, char *))[hash_name_len - 1] = ':';
          KLM_SIZE_ADD_ATTR(rspsz, attr);

          // Each pconn may have one or more tokens
          HASH_ITER(pct_hh, desc.ad_persona.ad_pconn->pc_tokens, cur_tok, tmp_tok) {
            struct token *tok = cur_tok->pct_token;
            attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
            if ( !attr ) {
              fprintf(stderr, "Not enough space for tokens\n");
              break;
            }

            attr->kla_name = htons(KLA_TOKEN);
            attr->kla_length = htons(KLA_SIZE(TOKEN_ID_LENGTH));
            if ( !(KLA_DATA(attr, ret_buf, sizeof(ret_buf))) ) {
              fprintf(stderr, "Not enough space for token data\n");
              break;
            }
            memcpy(KLA_DATA_UNSAFE(attr, char *), tok->tok_token_id, TOKEN_ID_LENGTH);

            KLM_SIZE_ADD_ATTR(rspsz, attr);
          }

          pthread_mutex_unlock(&desc.ad_persona.ad_pconn->pc_mutex);
        } else {
          localsock_return_internal_error(api, el, msg);
        }

        break;

      case ARP_DESC_APP_INSTANCE:
        attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
        assert(attr);
        attr->kla_name = htons(KLA_CONTAINER_TYPE);
        attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));
        code = htons(desc.ad_container_type);
        memcpy(KLA_DATA_UNSAFE(attr, void *), &code, sizeof(code));
        KLM_SIZE_ADD_ATTR(rspsz, attr);

        attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
        assert(attr);
        attr->kla_name = htons(KLA_PERSONA_ID);
        attr->kla_length = htons(KLA_SIZE(PERSONA_ID_LENGTH));
        memcpy(KLA_DATA_UNSAFE(attr, void *), desc.ad_app_instance.ad_persona_id,
               PERSONA_ID_LENGTH);
        KLM_SIZE_ADD_ATTR(rspsz, attr);

        attr = KLM_NEXTATTR(rsp, attr, sizeof(ret_buf));
        assert(attr);
        attr->kla_name = htons(KLA_APP_URL);
        attr->kla_length = htons(KLA_SIZE(strlen(desc.ad_app_instance.ad_app_url)));
        memcpy(KLA_DATA_UNSAFE(attr, void *), desc.ad_app_instance.ad_app_url,
               strlen(desc.ad_app_instance.ad_app_url));
        KLM_SIZE_ADD_ATTR(rspsz, attr);

        break;

      default:
        code = htons(KLE_SYSTEM_ERROR);
        memcpy(KLA_DATA_UNSAFE(attr, void *), &code, sizeof(code));
        break;
      }

      arpdesc_release(&desc, sizeof(desc));
      localsock_respond(api, el, ret_buf, rspsz);
    }
  }
}

static void localsock_sub_container(struct localapi *api, struct eventloop *el,
                                    struct kitelocalmsg *msg, int msgsz,
                                    int *fds, int nfds) {
  struct kitelocalattr *attr;
  struct persona *persona = NULL;
  struct app *app = NULL;

  struct in_addr addr;
  addr.s_addr = 0;

  int stdin_fd = -1, stdout_fd = -1, stderr_fd = -1, err;
  uint8_t fdix;

  struct buffer args;

  buffer_init(&args);

  for ( attr = KLM_FIRSTATTR(msg, msgsz);
        attr;
        attr = KLM_NEXTATTR(msg, attr, msgsz) ) {
    switch ( KLA_NAME(attr) ) {
    case KLA_ADDR:
      if ( KLA_PAYLOAD_SIZE(attr) == sizeof(addr) ) {
        memcpy(&addr.s_addr, KLA_DATA_UNSAFE(attr, void *), sizeof(addr.s_addr));
      }
      break;

    case KLA_PERSONA_ID:
      if ( KLA_PAYLOAD_SIZE(attr) == PERSONA_ID_LENGTH && !persona ) {
        // Look up this persona. If we have this persona, and this
        // application ID, attempt to launch the application instance
        err = appstate_lookup_persona(api->la_app_state, KLA_DATA_UNSAFE(attr, const char *), &persona);
        if ( err < 0 ) {
          localsock_return_not_found(api, el, msg);
          goto done;
        }
      }
      break;

    case KLA_APP_URL:
      if ( !app ) {
        app = appstate_get_app_by_url_ex(api->la_app_state, KLA_DATA_UNSAFE(attr, const char*), KLA_PAYLOAD_SIZE(attr));
        if ( !app ) {
          localsock_return_not_found(api, el, msg);
          goto done;
        }
      }
      break;

    case KLA_STDIN:
    case KLA_STDOUT:
    case KLA_STDERR:
      if ( KLA_PAYLOAD_SIZE(attr) == sizeof(fdix) ) {
        int new_fd;
        memcpy(&fdix, KLA_DATA_UNSAFE(attr, void*), sizeof(fdix));

        if ( fdix < nfds ) {
          new_fd = fds[fdix];

          if ( KLA_NAME(attr) == KLA_STDIN )
            stdin_fd = new_fd;
          else if ( KLA_NAME(attr) == KLA_STDOUT )
            stdout_fd = new_fd;
          else
            stderr_fd = new_fd;
        }
      }
      break;

    case KLA_ARG:
      buffer_write(&args, KLA_DATA_UNSAFE(attr, void *), KLA_PAYLOAD_SIZE(attr));
      buffer_write(&args, " ", 1);
      break;

    default: break;
    };
  };

  if ( addr.s_addr == 0 && !persona && !app ) {
    buffer_release(&args);
    localsock_return_missing_attrs(api, el, msg, KLM_REQ_ENTITY(msg), KLM_REQ_OP(msg),
                                   KLA_ADDR, -1);
  } else if ( addr.s_addr != 0 && (persona || app) ) {
    buffer_release(&args);
    localsock_return_bad_method(api, el, msg, KLM_REQ_ENTITY(msg), KLM_REQ_OP(msg));
  } else if ( persona && !app ) {
    buffer_release(&args);
    localsock_return_missing_attrs(api, el, msg, KLM_REQ_ENTITY(msg), KLM_REQ_OP(msg),
                                   KLA_APP_URL, -1);
  } else {
    struct appinstance *ai = NULL;
    const char *argv[4] = { "-sh", "-c", NULL, NULL };
    int child_pid;

    if ( addr.s_addr != 0 ) {
      struct arpdesc desc;

      err = bridge_describe_arp(&api->la_app_state->as_bridge,
                                &addr, &desc, sizeof(desc));
      if ( err == 0 ) {
        localsock_return_not_found(api, el, msg);
        goto done;
      } else if ( err < 0 ) {
        localsock_return_internal_error(api, el, msg);
        goto done;
      }

      if ( desc.ad_container_type != ARP_DESC_APP_INSTANCE ) {
        arpdesc_release(&desc, sizeof(desc));
        localsock_return_not_allowed(api, el, msg);
        goto done;
      } else {
        ai = desc.ad_app_instance.ad_app_instance;
        APPINSTANCE_REF(ai);
        arpdesc_release(&desc, sizeof(desc));
      }
    } else if ( app ) {
      ai = launch_app_instance(api->la_app_state, persona, app);
      if ( !ai ) {
        localsock_return_not_found(api, el, msg);
        goto done;
      }
    }

    if ( !ai ) {
      buffer_release(&args);
    } else {
      struct containerexecinfo exec_options;
      const char *final_arg;

      buffer_finalize_str(&args, &final_arg);
      argv[2] = final_arg;

      exec_options.cei_flags = CONTAINER_EXEC_ENABLE_WAIT;
      exec_options.cei_exec = "/bin/sh";
      exec_options.cei_argv = argv;
      exec_options.cei_envv = NULL;

      if ( stdin_fd >= 0 ) {
        exec_options.cei_flags |= CONTAINER_EXEC_REDIRECT_STDIN;
        exec_options.cei_stdin_fd = stdin_fd;
      }

      if ( stdout_fd >= 0 ) {
        exec_options.cei_flags |= CONTAINER_EXEC_REDIRECT_STDOUT;
        exec_options.cei_stdout_fd = stdout_fd;
      }

      if ( stderr_fd >= 0 ) {
        exec_options.cei_flags |= CONTAINER_EXEC_REDIRECT_STDERR;
        exec_options.cei_stderr_fd = stderr_fd;
      }

      child_pid = container_execute_ex(&ai->inst_container, &exec_options);
      if ( child_pid < 0 ) {
        fprintf(stderr, "There was an error running the child\n");
        free((void *)final_arg);
        localsock_return_internal_error(api, el, msg);
      } else {
        free((void *)final_arg);
        fprintf(stderr, "Launched container child with pid %d\n", child_pid);
        // Wait for the child to complete
        api->la_container_sts_fd = exec_options.cei_wait_fd;
        fprintf(stderr, "Got wait fd %d\n", exec_options.cei_wait_fd);

        set_socket_nonblocking(api->la_container_sts_fd);
        fdsub_init(&api->la_container_completion, el, api->la_container_sts_fd,
                   OP_LOCALAPI_CONTAINER_CMD_COMPLETE, localsockfn);
        eventloop_subscribe_fd(el,api->la_container_sts_fd,
                               FD_SUB_READ, &api->la_container_completion);
        api->la_busy = 1;
        fprintf(stderr, "There is currently %d bytes outgoing\n",
                api->la_outgoing_sz);
      }

      APPINSTANCE_UNREF(ai);
    }
  }

 done:
  if ( stdin_fd > 0 ) close(stdin_fd);
  if ( stdout_fd > 0 ) close(stdout_fd);
  if ( stderr_fd > 0 ) close(stderr_fd);

  if ( persona ) PERSONA_UNREF(persona);
  if ( app ) APPLICATION_UNREF(app);
}

static void localsock_update_container(struct localapi *api, struct eventloop *el,
                                       struct kitelocalmsg *msg, int msgsz) {
  struct kitelocalattr *attr;
  const char *cred = NULL;
  size_t credsz = 0;
  int err;
  struct arpdesc desc;

  struct in_addr addr;
  addr.s_addr = 0;

  for ( attr = KLM_FIRSTATTR(msg, msgsz);
        attr;
        attr = KLM_NEXTATTR(msg, attr, msgsz) ) {
    switch ( KLA_NAME(attr) ) {
    case KLA_CRED:
      if ( cred ) {
        localsock_return_bad_method(api, el, msg, KLM_REQ_ENTITY_CONTAINER, KLM_REQ_UPDATE);
        return;
      } else {
        cred = KLA_DATA_UNSAFE(attr, const char *);
        credsz = KLA_PAYLOAD_SIZE(attr);
      }
      break;

    case KLA_ADDR:
      if ( KLA_PAYLOAD_SIZE(attr) == sizeof(addr) ) {
        memcpy(&addr.s_addr, KLA_DATA_UNSAFE(attr, void *), sizeof(addr.s_addr));
      }
      break;

    default:
      break;
    }
  }

  if ( addr.s_addr == 0 ) {
    localsock_return_missing_attrs(api, el, msg, KLM_REQ_ENTITY_CONTAINER, KLM_REQ_UPDATE, KLA_ADDR, -1);
    return;
  }

  if ( !cred ) {
    localsock_return_simple(api, el, msg, KLE_SUCCESS);
    return;
  }

  err = bridge_describe_arp(&api->la_app_state->as_bridge, &addr, &desc, sizeof(desc));
  if ( err == 0 ) {
    localsock_return_not_found(api, el, msg);
  } else if ( err < 0 )
    localsock_return_internal_error(api, el, msg);
  else {
    switch ( desc.ad_container_type ) {
    case ARP_DESC_PERSONA:
      if ( pthread_mutex_lock(&desc.ad_persona.ad_pconn->pc_mutex) == 0 ) {
        err = persona_credential_validates(desc.ad_persona.ad_pconn->pc_persona,
                                           desc.ad_persona.ad_pconn,
                                           cred, credsz);
        pthread_mutex_unlock(&desc.ad_persona.ad_pconn->pc_mutex);
        if ( err <= 0 ) {
          localsock_return_simple(api, el, msg, KLE_NOT_ALLOWED);
        } else {
          localsock_return_simple(api, el, msg, KLE_SUCCESS);
        }
      } else
        localsock_return_internal_error(api, el, msg);
      break;

    default:
      localsock_return_simple(api, el, msg, KLE_BAD_ENTITY);
    }
    arpdesc_release(&desc, sizeof(desc));
  }
}

static void localsock_crud_container(struct localapi *api, struct eventloop *el,
                                     struct kitelocalmsg *msg, int msgsz,
                                     int *fds, int nfds) {
  switch ( KLM_REQ_OP(msg) ) {
  case KLM_REQ_GET:
    localsock_get_container(api, el, msg, msgsz);
    break;

  case KLM_REQ_UPDATE:
    localsock_update_container(api, el, msg, msgsz);
    break;

  case KLM_REQ_SUB:
    localsock_sub_container(api, el, msg, msgsz, fds, nfds);
    break;

  default:
    localsock_return_bad_method(api, el, msg, KLM_REQ_ENTITY(msg), KLM_REQ_OP(msg));
    break;
  }
}

static void localsock_handle_message(struct localapi *api, struct eventloop *el,
                                     const char *buf, int buf_sz, struct msghdr *skmsg) {
  struct kitelocalmsg *msg;
  struct cmsghdr *cmsg;
  int fds[10], nfds = 0, i;

  //fprintf(stderr, "Received local message of size %d (control " CMSGLEN_LD ")\n", buf_sz, skmsg->msg_controllen);

  if ( buf_sz < sizeof(*msg) ) {
    // Ignore message
    fprintf(stderr, "Ignoring tiny request\n");
    localsock_hup(api, el);
    return;
  }

  for ( cmsg = CMSG_FIRSTHDR(skmsg);
        cmsg;
        cmsg = CMSG_NXTHDR(skmsg, cmsg) ) {
    if ( cmsg->cmsg_level == SOL_SOCKET &&
         cmsg->cmsg_type == SCM_RIGHTS &&
         (cmsg->cmsg_len % sizeof(*fds)) == 0 &&
         cmsg->cmsg_len <= CMSG_LEN(sizeof(fds)) ) {

      nfds = (cmsg->cmsg_len - sizeof(struct cmsghdr)) / sizeof(*fds);
      memcpy(fds, CMSG_DATA(cmsg), nfds * sizeof(*fds));

    } else {
      fprintf(stderr, "Received unknown local control message (level=%d, type=%d, length=" CMSGLEN_LD ")\n",
              cmsg->cmsg_level, cmsg->cmsg_type, cmsg->cmsg_len);
    }
  }

  msg = (struct kitelocalmsg *) buf;

  switch( KLM_REQ_ENTITY(msg) ) {
  case KLM_REQ_ENTITY_PERSONA:
    localsock_crud_persona(api, el, msg, buf_sz);
    break;
  case KLM_REQ_ENTITY_APP:
    localsock_crud_app(api, el, msg, buf_sz, fds, nfds);
    break;
  case KLM_REQ_ENTITY_FLOCK:
    localsock_crud_flock(api, el, msg, buf_sz);
    break;
  case KLM_REQ_ENTITY_CONTAINER:
    localsock_crud_container(api, el, msg, buf_sz, fds, nfds);
    break;
  case KLM_REQ_ENTITY_SYSTEM:
    localsock_crud_system(api, el, msg, buf_sz);
    break;
  default:
    localsock_return_bad_entity(api, el, msg, KLM_REQ_ENTITY(msg));
    break;
  }

  for ( i = 0; i < nfds; ++i )
    close(fds[i]);
}

static int localsock_list_current( struct localapi *api, struct eventloop *el,
                                   int is_empty ) {
  struct persona *p;

  char buf[KITE_MAX_LOCAL_MSG_SZ];
  struct kitelocalmsg *msg;
  struct kitelocalattr *attr;
  int sz = KLM_SIZE_INIT;
  uint16_t return_code = htons(KLE_SUCCESS);

  msg = (struct kitelocalmsg *)buf;
  attr = KLM_FIRSTATTR(msg, sizeof(buf));

  assert (attr);

  msg->klm_req = htons(KLM_RESPONSE | api->la_listing_ent | KLM_REQ_GET);
  msg->klm_req_flags = KLM_RETURN_MULTIPLE;

  if ( is_empty || (api->la_listing_offs + 1) >= api->la_listing_count ||
       !api->la_listing[api->la_listing_offs + 1] )
    msg->klm_req_flags |= KLM_IS_LAST;

  msg->klm_req_flags = htons(msg->klm_req_flags);

  attr->kla_name = htons(KLA_RESPONSE_CODE);
  attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));
  memcpy(KLA_DATA_UNSAFE(attr, void *), &return_code, sizeof(uint16_t));
  KLM_SIZE_ADD_ATTR(sz, attr);

  if ( !is_empty ) {
    struct shared *cur;
    cur = api->la_listing[api->la_listing_offs];

    switch ( api->la_listing_ent ) {
    case KLM_REQ_ENTITY_PERSONA:
      p = STRUCT_FROM_BASE(struct persona, p_shared, cur);

      attr = KLM_NEXTATTR(msg, attr, sizeof(buf));
      attr->kla_name = htons(KLA_PERSONA_ID);
      attr->kla_length = htons(KLA_SIZE(PERSONA_ID_LENGTH));
      memcpy(KLA_DATA_UNSAFE(attr, void*), p->p_persona_id, PERSONA_ID_LENGTH);
      KLM_SIZE_ADD_ATTR(sz, attr);

      return localsock_respond(api, el, buf, sz);

    default:
      fprintf(stderr, "localsock_list_current: unknown entity %d\n", api->la_listing_ent);
      return 0;
    }
  } else
    return localsock_respond(api, el, buf, sz);
}

static void localsock_do_list(struct localapi *api, struct eventloop *el) {
  for ( ; api->la_listing_offs < api->la_listing_count; ++api->la_listing_offs ) {
    struct shared *cur = api->la_listing[api->la_listing_offs];
    if ( !cur ) break; // Done

    if ( localsock_list_current(api, el, 0) < 0 ) {
      return;
    } else {
      SHARED_UNREF(cur);
      api->la_listing[api->la_listing_offs] = NULL;
    }
  }

  if ( api->la_listing_count == 0 ) {
    // Empty response
    localsock_list_current(api, el, 1);
  }

  api->la_busy = 0;
  localsock_free_listing(api);
}

static int localsock_flush(struct localapi *api, struct eventloop *el) {
  int outgoing_ptr = 0, err;

  while ( (outgoing_ptr + 4) < api->la_outgoing_sz ) {
    uint32_t *sz_ptr, sz;
    char *outgoing = api->la_outgoing;

    sz_ptr = (uint32_t *) (api->la_outgoing + outgoing_ptr);
    sz = *sz_ptr;
    outgoing += outgoing_ptr + 4;

    if ( outgoing_ptr + 4 + sz > api->la_outgoing_sz ) {
      fprintf(stderr, "localsock_flush: fault: underflow\n");
      return -1;
    }

    err = send(api->la_socket, outgoing, sz, 0);
    if ( err < 0 ) {
      if ( errno == EWOULDBLOCK ) break;
      perror("localsock_flush: send");
      return -1;
    }

    outgoing_ptr += 4 + sz;
  }

  if ( (outgoing_ptr + 4) < api->la_outgoing_sz ) {
    memcpy(api->la_outgoing, api->la_outgoing + outgoing_ptr, api->la_outgoing_sz - outgoing_ptr);
    api->la_outgoing_sz -= outgoing_ptr;
  } else
    api->la_outgoing_sz = 0;

  return 0;
}

static void localsock_cmd_completes(struct localapi *api, int sts) {
  struct eventloop *el = &api->la_app_state->as_eventloop;
  char buf[KITE_MAX_LOCAL_MSG_SZ];
  struct kitelocalmsg *msg;
  struct kitelocalattr *attr;
  int sz = KLM_SIZE_INIT;
  uint16_t code = KLE_SUCCESS;
  uint32_t usts = sts;

  msg = (struct kitelocalmsg *)buf;
  msg->klm_req = htons(KLM_RESPONSE | KLM_REQ_SUB | KLM_REQ_ENTITY_CONTAINER);
  msg->klm_req_flags = 0;

  attr = KLM_FIRSTATTR(msg, sizeof(buf));
  attr->kla_name = htons(KLA_RESPONSE_CODE);
  attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));
  code = htons(code);
  memcpy(KLA_DATA_UNSAFE(attr, void *), &code, sizeof(code));
  KLM_SIZE_ADD_ATTR(sz, attr);

  attr = KLM_NEXTATTR(msg, attr, sizeof(buf));
  attr->kla_name = htons(KLA_EXIT_CODE);
  attr->kla_length = htons(KLA_SIZE(sizeof(usts)));
  usts = htonl(usts);
  memcpy(KLA_DATA_UNSAFE(attr, void *), &usts, sizeof(usts));
  KLM_SIZE_ADD_ATTR(sz, attr);

  localsock_respond(api, el, buf, sz);
}

static void localsock_update_completes(struct localapi *api) {
  struct eventloop *el = &api->la_app_state->as_eventloop;
  char buf[KITE_MAX_LOCAL_MSG_SZ];
  struct kitelocalmsg *msg;
  struct kitelocalattr *attr;
  int sz = KLM_SIZE_INIT;

  msg = (struct kitelocalmsg *)buf;
  attr = KLM_FIRSTATTR(msg, sizeof(buf));
  attr->kla_name = htons(KLA_RESPONSE_CODE);
  attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));

  msg->klm_req = htons(KLM_RESPONSE | KLM_REQ_CREATE | KLM_REQ_ENTITY_APP);
  msg->klm_req_flags = 0;

  if ( api->la_current_updater ) {
    struct appupdater *au = api->la_current_updater;
    api->la_current_updater = NULL;

    if ( au->au_sts == AU_STATUS_DONE ) {
      *KLA_DATA_AS(attr, buf, sizeof(buf), uint16_t *) = htons(KLE_SUCCESS);
    } else if ( au->au_sts < 0 ) {
      *KLA_DATA_AS(attr, buf, sizeof(buf), uint16_t *) = htons(KLE_SYSTEM_ERROR);
    } else {
      *KLA_DATA_AS(attr, buf, sizeof(buf), uint16_t *) = htons(KLE_NOT_IMPLEMENTED);
    }
    KLM_SIZE_ADD_ATTR(sz, attr);

    APPUPDATER_UNREF(au);
  } else {
    *KLA_DATA_AS(attr, buf, sizeof(buf), uint16_t *) = htons(KLE_SYSTEM_ERROR);
  }

  localsock_respond(api, el, buf, sz);

  api->la_busy = 0;
  LOCALAPI_SUBSCRIBE(el, api);
}
