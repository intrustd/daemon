#include <assert.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <uriparser/Uri.h>

#include "local.h"
#include "util.h"
#include "flock.h"
#include "update.h"

#define OP_LOCALAPI_RECV_MSG EVT_CTL_CUSTOM
#define OP_LOCALAPI_UPDATE_COMPLETE (EVT_CTL_CUSTOM + 1)

#define LOCALAPI_SUBSCRIBE(el, api)                                     \
  eventloop_subscribe_fd((el), (api)->la_socket,                        \
                         ((api)->la_busy ? 0 : FD_SUB_READ) |           \
                         ((api)->la_outgoing_sz >= 4 ? FD_SUB_WRITE : 0), \
                         &(api)->la_socket_sub);

struct localapi {
  struct appstate *la_app_state;

  int la_socket;
  struct fdsub la_socket_sub;

  struct qdevtsub la_update_completion;
  int la_busy : 1;

  struct appupdater *la_current_updater;

  char la_outgoing[KITE_MAX_LOCAL_MSG_SZ];
  int la_outgoing_sz;
};

static void localsock_hup(struct localapi *api, struct eventloop *el);
static void localsock_handle_message(struct localapi *api, struct eventloop *el,
                                     const char *buf, int buf_sz);
static int localsock_flush(struct localapi *api, struct eventloop *el);
static void localsock_update_completes(struct localapi *api);

static void localsockfn(struct eventloop *el, int op, void *arg) {
  struct localapi *api;
  struct fdevent *fde;
  struct qdevent *qde;
  int err;

  char buf[KITE_MAX_LOCAL_MSG_SZ];

  switch ( op ) {
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
    }

    if ( FD_READ_PENDING(fde) && !api->la_busy ) {
      err = recv(api->la_socket, buf, sizeof(buf), 0);
      if ( err <= 0 ) {
        if ( err < 0 )
          perror("localsockfn: recv");
        localsock_hup(api, el);
        return;
      }

      localsock_handle_message(api, el, buf, err);
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

  ret->la_app_state = as;
  ret->la_socket = sk;
  ret->la_busy = 0;
  ret->la_outgoing_sz = 0;
  fdsub_init(&ret->la_socket_sub, &as->as_eventloop, ret->la_socket, OP_LOCALAPI_RECV_MSG, localsockfn);

  qdevtsub_init(&ret->la_update_completion, OP_LOCALAPI_UPDATE_COMPLETE, localsockfn);
  eventloop_subscribe_fd(&as->as_eventloop, ret->la_socket, FD_SUB_READ, &ret->la_socket_sub);

  fprintf(stderr, "Opened local connection %p\n", ret);
  return ret;

 error:
  free(ret);
  return NULL;
}

static void localsock_hup(struct localapi *api, struct eventloop *el) {
  fprintf(stderr, "Local connection (%p) closing\n", api);

  if ( api->la_socket ) {
    eventloop_unsubscribe_fd(el, api->la_socket, FD_SUB_ALL, &api->la_socket_sub);
    close(api->la_socket);
  }

  if ( api->la_current_updater )
    APPUPDATER_UNREF(api->la_current_updater);

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

static int localsock_return_simple(struct localapi *api, struct eventloop *el,
                                   struct kitelocalmsg *in_response_to,
                                   uint16_t code) {
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
  *KLA_DATA_AS(attr, buf, sizeof(buf), uint16_t *) = htons(code);
  KLM_SIZE_ADD_ATTR(sz, attr);

  return localsock_respond(api, el, buf, sz);
}

static int localsock_return_not_found(struct localapi *api, struct eventloop *el,
                                      struct kitelocalmsg *in_response_to) {
  return localsock_return_simple(api, el, in_response_to, KLE_NOT_FOUND);
}

static int localsock_return_internal_error(struct localapi *api, struct eventloop *el,
                                           struct kitelocalmsg *in_response_to) {
  return localsock_return_simple(api, el, in_response_to, KLE_SYSTEM_ERROR);
}

static void localsock_crud_persona(struct localapi *api, struct eventloop *el,
                                   struct kitelocalmsg *msg, int msgsz) {
  char ret_buf[KITE_MAX_LOCAL_MSG_SZ];

  struct kitelocalmsg *rsp = (struct kitelocalmsg *) ret_buf;
  struct kitelocalattr *attr;

  struct persona *persona;

  char *display_name = NULL, *password = NULL;
  int display_name_sz = 0, password_sz = 0;

  int rspsz = KLM_SIZE_INIT;

  rsp->klm_req = htons(KLM_RESPONSE | htons(msg->klm_req));
  rsp->klm_req_flags = 0;

  attr = KLM_FIRSTATTR(rsp, sizeof(ret_buf));
  assert(attr);

  attr->kla_name = htons(KLA_RESPONSE_CODE);
  attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));

  switch ( KLM_REQ_OP(msg) ) {
  case KLM_REQ_CREATE:
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
      default:
        goto bad_request;
      }
    }
    if ( !display_name || !password )
      goto bad_request;

    if ( appstate_create_persona(api->la_app_state, display_name, display_name_sz,
                                 password, password_sz, &persona) < 0 ) {
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

    break;

  default:
    goto bad_request;
  }
  return;

 bad_request:
  attr = KLM_FIRSTATTR(rsp, sizeof(ret_buf));
  assert(attr);
  // TODO consolidate
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
      fprintf(stderr, "returning flock\n");
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

static void localsock_crud_app(struct localapi *api, struct eventloop *el,
                               struct kitelocalmsg *msg, int msgsz) {
  char ret_buf[KITE_MAX_LOCAL_MSG_SZ];

  struct kitelocalmsg *rsp = (struct kitelocalmsg *) ret_buf;
  struct kitelocalattr *attr;

  const char *app_uri;
  size_t app_uri_sz;

  int rspsz = KLM_SIZE_INIT, found_app_manifest = 0, do_force = 0;

  rsp->klm_req = htons(KLM_RESPONSE | htons(msg->klm_req));
  rsp->klm_req_flags = 0;

  attr = KLM_FIRSTATTR(rsp, sizeof(ret_buf));
  assert(attr);

  attr->kla_name = htons(KLA_RESPONSE_CODE);
  attr->kla_length = htons(KLA_SIZE(sizeof(uint16_t)));

  switch ( KLM_REQ_OP(msg) ) {
  case KLM_REQ_CREATE:
    fprintf(stderr, "Request to create app\n");
    for ( attr = KLM_FIRSTATTR(msg, msgsz); attr; attr = KLM_NEXTATTR(msg, attr, msgsz) ) {
      switch ( KLA_NAME(attr) ) {
      case KLA_APP_MANIFEST_URL:
        app_uri = KLA_DATA_UNSAFE(attr, char *);
        app_uri_sz = KLA_PAYLOAD_SIZE(attr);
        found_app_manifest = 1;
        break;

      case KLA_FORCE:
        do_force = 1;
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
      struct appupdater *u = appstate_queue_update_ex(api->la_app_state, app_uri, app_uri_sz,
                                                      AU_UPDATE_REASON_MANUAL, NULL);
      if ( !u ) {
        *(KLA_DATA_UNSAFE(attr, uint16_t *)) = htons(KLE_SYSTEM_ERROR);
        KLM_SIZE_ADD_ATTR(rspsz, attr);
        localsock_respond(api, el, ret_buf, rspsz);
        return;
      }

      fprintf(stderr, "appupdater: got force %d\n", do_force);

      appupdater_request_event(u, &api->la_update_completion);
      if ( do_force ) appupdater_force(u);
      appupdater_start(u);
      api->la_busy = 1;
      api->la_current_updater = u;
    }
    break;

  default:
    goto bad_request;
  }
  return;

 bad_request:
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

static void localsock_get_container(struct localapi *api, struct eventloop *el,
                                    struct kitelocalmsg *msg, int msgsz) {
  struct kitelocalattr *attr;

  struct in_addr addr;
  addr.s_addr = 0;

  fprintf(stderr, "Request to get container\n");

  for ( attr = KLM_FIRSTATTR(msg, msgsz); attr; attr = KLM_NEXTATTR(msg, attr, msgsz) ) {
    switch ( KLA_NAME(attr) ) {
    case KLA_ADDR:
      fprintf(stderr, "got kla addr %ld\n", KLA_PAYLOAD_SIZE(attr));
      if ( KLA_PAYLOAD_SIZE(attr) == sizeof(addr) ) {
        memcpy(&addr.s_addr, KLA_DATA_UNSAFE(attr, void *), sizeof(addr.s_addr));
      }
      break;

    default:break;
    }
  }

  if ( addr.s_addr == 0 ){
    localsock_return_bad_method(api, el, msg, KLM_REQ_ENTITY(msg), KLM_REQ_OP(msg));
  } else {
    int err;
    char str[INET_ADDRSTRLEN + 1];
    struct arpdesc desc;
    fprintf(stderr, "Going to lookup infermation for %s\n", inet_ntop(AF_INET, &addr, str, sizeof(str)));

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

      localsock_respond(api, el, ret_buf, rspsz);
    }
  }
}

static void localsock_crud_container(struct localapi *api, struct eventloop *el,
                                     struct kitelocalmsg *msg, int msgsz) {
  switch ( KLM_REQ_OP(msg) ) {
  case KLM_REQ_GET:
    localsock_get_container(api, el, msg, msgsz);
    break;

  default:
    localsock_return_bad_method(api, el, msg, KLM_REQ_ENTITY(msg), KLM_REQ_OP(msg));
    break;
  }
}

static void localsock_handle_message(struct localapi *api, struct eventloop *el,
                                     const char *buf, int buf_sz) {
  struct kitelocalmsg *msg;

  fprintf(stderr, "Received local message of size %d\n", buf_sz);

  if ( buf_sz < sizeof(*msg) ) {
    // Ignore message
    fprintf(stderr, "Ignoring tiny request\n");
    localsock_hup(api, el);
    return;
  }

  msg = (struct kitelocalmsg *) buf;

  switch( KLM_REQ_ENTITY(msg) ) {
  case KLM_REQ_ENTITY_PERSONA:
    localsock_crud_persona(api, el, msg, buf_sz);
    break;
  case KLM_REQ_ENTITY_APP:
    localsock_crud_app(api, el, msg, buf_sz);
    break;
  case KLM_REQ_ENTITY_FLOCK:
    localsock_crud_flock(api, el, msg, buf_sz);
    break;
  case KLM_REQ_ENTITY_CONTAINER:
    localsock_crud_container(api, el, msg, buf_sz);
    break;
  default:
    localsock_return_bad_entity(api, el, msg, KLM_REQ_ENTITY(msg));
    break;
  }
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
  }

  return 0;
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
