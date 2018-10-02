#include <stdio.h>
#include <alloca.h>
#include <ctype.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>

#include "sdp.h"
#include "util.h"

#define SDP_ERROR(err) do {                             \
    (st)->sps_mode = (err);                             \
    return (err);                                       \
  } while (0)

static int sdp_end_of_line(struct sdpparsest *st) {
  for ( ; st->sps_line[st->sps_column_pos] != '\0' &&
          isspace(st->sps_line[st->sps_column_pos]);
        st->sps_column_pos++ );

  return st->sps_line[st->sps_column_pos] == '\0';
}

// Skip one or more spaces. Returns 1 if one or more spaces were skipped. 0 otherwise
static int sdp_skip_space(struct sdpparsest *st) {
  int start = st->sps_column_pos;

  for ( ; st->sps_line[st->sps_column_pos] != '\0' &&
          isspace(st->sps_line[st->sps_column_pos]);
        st->sps_column_pos++ );

  return st->sps_column_pos > start;
}

static int sdp_parse_exact(struct sdpparsest *st, const char *token) {
  int i = 0;

  for ( i = 0;
        st->sps_line[st->sps_column_pos] != '\0' &&
          token[i] != '\0' && st->sps_line[st->sps_column_pos] == token[i];
        st->sps_column_pos++, i++ );

  if ( token[i] == '\0' ) return 1;

  return 0;
}

// Parse string until one of the characters in delim. Return number of
// characters parsed or -1 on error.
static int sdp_parse_string_until(struct sdpparsest *st, char *dst, size_t dst_sz,
                                  const char *delim) {
  int i;

  for ( i = 0;
        st->sps_line[st->sps_column_pos] != '\0' && (dst ? i < dst_sz : 1) &&
          !strchr(delim, st->sps_line[st->sps_column_pos]);
        ++st->sps_column_pos, ++i )
    if ( dst )
      dst[i] = st->sps_line[st->sps_column_pos];

  if ( dst ) {
    if ( i >= dst_sz ) { dst[0] = '\0'; return -1; }
    dst[i] = '\0';
  }

  return i;
}

// Consume the entire rest of the line, returning the number of
// characters consumed, or -1 on error
static int sdp_consume_rest(struct sdpparsest *st, char *dst, size_t dst_sz) {
  int i;

  for ( i = 0; st->sps_line[st->sps_column_pos] != '\0' &&
          (dst ? i < dst_sz : 1);
        ++i, ++st->sps_column_pos )
    if ( dst )
      dst[i] = st->sps_line[st->sps_column_pos];

  if ( dst ) {
    if ( i >= dst_sz ) { dst[0] = '\0'; return -1; }
    dst[i] = '\0';
  }

  return i;
}

static int sdp_next_char(struct sdpparsest *st) {
  if ( st->sps_line[st->sps_column_pos] == '\0' )
    return -1;

  return st->sps_line[st->sps_column_pos++];
}

static int sdp_positive_decimal(struct sdpparsest *st, int *out) {
  int consumed = parse_decimal(out, st->sps_line + st->sps_column_pos,
                               strlen(st->sps_line) - st->sps_column_pos);
  if ( consumed < 0 )
    return 0;

  st->sps_column_pos += consumed;

  return 1;
}

static void sdp_skip_until_space(struct sdpparsest *st) {
  while ( st->sps_line[st->sps_column_pos] != '\0' &&
          st->sps_line[st->sps_column_pos] != ' ' )
    st->sps_column_pos++;
}

static int sdp_parse_attribute(struct sdpparsest *st, const char **nmsp, const char **nmep,
                               const char **vlsp, const char **vlep) {
  int err;
  const char *nms, *nme, *vls, *vle;

  nms = nme = vls = vle = *nmsp = *nmep = *vlsp = *vlep = NULL;

  nms = &st->sps_line[st->sps_column_pos];

  err = sdp_parse_string_until(st, NULL, 0, ":");
  if ( err < 0 ) SDP_ERROR(SPS_MISSING_ATTRIBUTE_NAME);


  nme = &st->sps_line[st->sps_column_pos];

  if ( st->sps_line[st->sps_column_pos] == '\0' ) {
    *nmsp = nms;
    *nmep = nme;
    *vlsp = *vlep = NULL;
    return 0;
  } else if ( st->sps_line[st->sps_column_pos] != ':' )
    SDP_ERROR(SPS_MISSING_COLON);
  else {
    st->sps_column_pos++;

    vls = &st->sps_line[st->sps_column_pos];
    err = sdp_consume_rest(st, NULL, 0);
    if ( err < 0 ) return err;

    vle = &st->sps_line[st->sps_column_pos];
    if (vls == vle )
      SDP_ERROR(SPS_MISSING_ATTRIBUTE_VALUE);

    *nmsp = nms;
    *nmep = nme;
    *vlsp = vls;
    *vlep = vle;

    return 0;
  }
}

static int sdp_parse_new_media(struct sdpparsest *st) {
  char tmp[SPS_NAME_LEN];
  int err, port_start = 0, port_count = 1;
  uint16_t ports[2];

  if ( st->sps_new_media_fn(st->sps_user_data) < 0 )
    SDP_ERROR(SPS_INVALID_MEDIA);

  err = sdp_parse_string_until(st, tmp, sizeof(tmp), " ");
  if ( err < 0 ) SDP_ERROR(SPS_NAME_TOO_LONG);

  if ( st->sps_media_ctl_fn(st->sps_user_data, SPS_MEDIA_SET_TYPE, tmp) == -1 )
    SDP_ERROR(SPS_INVALID_MEDIA_TYPE);

  if ( !sdp_skip_space(st) )
    SDP_ERROR(SPS_INVALID_MEDIA);

  if ( !sdp_positive_decimal(st, &port_start) )
    SDP_ERROR(SPS_INVALID_MEDIA);

  if ( st->sps_line[st->sps_column_pos] == '/' ) {
    st->sps_column_pos++;
    if ( !sdp_positive_decimal(st, &port_count) )
      SDP_ERROR(SPS_INVALID_MEDIA);
  } else
    port_count = 1;

  ports[0] = port_start;
  ports[1] = port_count;

  if ( st->sps_media_ctl_fn(st->sps_user_data, SPS_MEDIA_SET_PORTS, ports) == -1 )
    SDP_ERROR(SPS_INVALID_MEDIA_PORTS);

  if ( !sdp_skip_space(st) )
    SDP_ERROR(SPS_INVALID_MEDIA);

  err = sdp_parse_string_until(st, tmp, sizeof(tmp), " ");
  if ( err < 0 ) SDP_ERROR(SPS_NAME_TOO_LONG);

  if ( st->sps_media_ctl_fn(st->sps_user_data, SPS_MEDIA_SET_PROTOCOL, tmp) == -1 )
    SDP_ERROR(SPS_INVALID_MEDIA_PROTOCOL);

  if ( !sdp_skip_space(st) )
    SDP_ERROR(SPS_INVALID_MEDIA);

  err = sdp_parse_string_until(st, tmp, sizeof(tmp), " ");
  if ( err < 0 ) SDP_ERROR(SPS_NAME_TOO_LONG);

  if ( st->sps_media_ctl_fn(st->sps_user_data, SPS_MEDIA_SET_FORMAT, tmp) == -1 )
    SDP_ERROR(SPS_INVALID_MEDIA_FORMAT);

  if ( !sdp_end_of_line(st) )
    SDP_ERROR(SPS_INVALID_MEDIA);

  return 0;
}

void sdp_reset(struct sdpparsest *st) {
  st->sps_mode = SPS_MODE_START;
  st->sps_line_mode = SPS_LINE_MODE_NORMAL;
  st->sps_line_num = 0;
  st->sps_column_pos = 0;
  st->sps_line[0] = '\0';
  st->sps_session_version = -1;
  st->sps_session_name[0] = '\0';
  st->sps_username[0] = '\0';
  st->sps_session_id[0] = '\0';
  st->sps_originator.ksa.sa_family = AF_UNSPEC;
  st->sps_flags = 0;
  st->sps_start_time = st->sps_end_time = 0;

  st->sps_global_connection.ksa.sa_family = AF_UNSPEC;
}

int sdp_init(struct sdpparsest *st, sdpnewmediafn new_media, sdpmediactlfn media_ctl,
             sdpattrfn attr, void *user) {
  st->sps_new_media_fn = new_media;
  st->sps_media_ctl_fn = media_ctl;
  st->sps_attr_fn = attr;
  st->sps_user_data = user;

  sdp_reset(st);
  return 0;
}

#define SDP_RETURN_ERROR return st->sps_mode
static int sdp_parse_line(struct sdpparsest *st) {
  char type;
  int line_length = strnlen(st->sps_line, sizeof(st->sps_line)), int_value;
  if ( line_length >= sizeof(st->sps_line) )
    SDP_ERROR(SPS_LINE_TOO_LONG);

  st->sps_line_num++;
  st->sps_column_pos = 0;

  if ( line_length < 2 ||
       st->sps_line[1] != '=' )
    SDP_ERROR(SPS_INVALID_TYPE);

  st->sps_column_pos = 2;

  type = st->sps_line[0];

  switch ( st->sps_mode ) {
  case SPS_MODE_START:
    if ( type == 'v' ) {
      if ( !sdp_positive_decimal(st, &int_value) )
        SDP_ERROR(SPS_INCOMPATIBLE_VERSION);
      else if ( int_value != 0 )
        SDP_ERROR(SPS_INCOMPATIBLE_VERSION);
      else {
        if ( !sdp_end_of_line(st) )
          SDP_ERROR(SPS_INVALID_VERSION);
        st->sps_mode = SPS_MODE_PARSED_SESSION_VERSION;
      }
    } else
      SDP_ERROR(SPS_INVALID_TYPE);
    break;

  case SPS_MODE_PARSED_SESSION_VERSION:
    if ( type == 'o' ) {
      int addr_type, addr_start, addr_end;
      char *addr_buf;

      if ( sdp_parse_string_until(st, st->sps_username, sizeof(st->sps_username), " ") <= 0 )
        SDP_ERROR(SPS_INVALID_ORIGINATOR);
      if ( !sdp_skip_space(st) )
        SDP_ERROR(SPS_INVALID_ORIGINATOR);

      if ( sdp_parse_string_until(st, st->sps_session_id, sizeof(st->sps_session_id), " ") <= 0)
        SDP_ERROR(SPS_INVALID_ORIGINATOR);
      if ( !sdp_skip_space(st) )
        SDP_ERROR(SPS_INVALID_ORIGINATOR);

      if ( !sdp_positive_decimal(st, &st->sps_session_version) )
        SDP_ERROR(SPS_INVALID_SESSION_VERSION);
      if ( !sdp_skip_space(st) )
        SDP_ERROR(SPS_INVALID_ORIGINATOR);

      if ( !sdp_parse_exact(st, "IN") )
        SDP_ERROR(SPS_INVALID_NET_TYPE);

      if ( !sdp_skip_space(st) )
        SDP_ERROR(SPS_INVALID_ORIGINATOR);

      if ( !sdp_parse_exact(st, "IP") )
        SDP_ERROR(SPS_INVALID_ADDR_TYPE);

      addr_type = sdp_next_char(st);
      if ( addr_type < 0 )
        SDP_ERROR(SPS_INVALID_ADDRESS);

      if ( !sdp_skip_space(st) )
        SDP_ERROR(SPS_INVALID_ORIGINATOR);

      addr_start = st->sps_column_pos;
      sdp_skip_until_space(st);
      addr_end = st->sps_column_pos;

      assert(addr_end >= addr_start);
      if ( addr_end == addr_start )
        SDP_ERROR(SPS_INVALID_ORIGINATOR);

      addr_buf = alloca(addr_end - addr_start + 1);
      memcpy(addr_buf, st->sps_line + addr_start, addr_end - addr_start);
      addr_buf[addr_end - addr_start] = '\0';

      switch ( addr_type ) {
      case '4':
        do {
          struct sockaddr_in *sin = (struct sockaddr_in *) &st->sps_originator;

          sin->sin_family = AF_INET;
          sin->sin_port = 0;

          if ( inet_pton(AF_INET,  addr_buf, &sin->sin_addr.s_addr) <= 0 )
            SDP_ERROR(SPS_INVALID_ADDRESS);
        } while (0);
        break;
      case '6':
        do {
          struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &st->sps_originator;

          memset(sin6, 0, sizeof(*sin6));

          sin6->sin6_family = AF_INET6;
          sin6->sin6_port = 0;

          if ( inet_pton(AF_INET6,  addr_buf, sin6->sin6_addr.s6_addr) <= 0 )
            SDP_ERROR(SPS_INVALID_ADDRESS);
        } while (0);
        break;
      default:
        SDP_ERROR(SPS_INVALID_ADDR_TYPE);
      }
      st->sps_mode = SPS_MODE_PARSED_SESSION_ORIGINATOR;
    } else
      SDP_ERROR(SPS_INVALID_TYPE);
    break;

  case SPS_MODE_PARSED_SESSION_ORIGINATOR:
    // Expect 's' tag
    if ( type == 's' ) {
      // Parse s
      if ( sdp_consume_rest(st, st->sps_session_name, sizeof(st->sps_session_name)) < 0)
        SDP_ERROR(SPS_NAME_TOO_LONG);
      if ( strnlen(st->sps_session_name, sizeof(st->sps_session_name)) > 0 )
        st->sps_mode = SPS_MODE_PARSED_SESSION_NAME;
      else
        SDP_ERROR(SPS_INVALID_SESSION_NAME);
    } else
      SDP_ERROR(SPS_INVALID_TYPE);
    break;

  case SPS_MODE_PARSED_SESSION_NAME:
    st->sps_mode = SPS_MODE_PARSED_SESSION_INFORMATION;
    if ( type == 'i' ) return SPS_SUCCESS;

  case SPS_MODE_PARSED_SESSION_INFORMATION:
    st->sps_mode = SPS_MODE_PARSED_SESSION_URI;
    if ( type == 'u' ) return SPS_SUCCESS;

  case SPS_MODE_PARSED_SESSION_URI:
    st->sps_mode = SPS_MODE_PARSED_SESSION_EMAIL;
    if ( type == 'e' ) return SPS_SUCCESS;

  case SPS_MODE_PARSED_SESSION_EMAIL:
    st->sps_mode = SPS_MODE_PARSED_SESSION_PHONE;
    if ( type == 'p' ) return SPS_SUCCESS;

  case SPS_MODE_PARSED_SESSION_PHONE:
    st->sps_mode = SPS_MODE_PARSED_SESSION_CONNECTION;
    if ( type == 'c' ) {
      st->sps_flags |= SPS_FLAG_GLOBAL_CONNECTION;
      // TODO parse connection

      return SPS_SUCCESS;
    }

  case SPS_MODE_PARSED_SESSION_CONNECTION:
    st->sps_mode = SPS_MODE_PARSED_SESSION_BANDWIDTH;
    if ( type == 'b' ) return SPS_SUCCESS;

  case SPS_MODE_PARSED_SESSION_BANDWIDTH:
    st->sps_mode = SPS_MODE_PARSED_SESSION_TIME;
    if ( type == 't' ) {
      // TODO
      return SPS_SUCCESS;
    }

  case SPS_MODE_PARSED_SESSION_TIME:
    st->sps_mode = SPS_MODE_PARSED_SESSION_RECURRENCE;
    if ( type == 'r' ) {
      st->sps_flags |= SPS_FLAG_RECURRENCE;
      return SPS_SUCCESS;
    }

  case SPS_MODE_PARSED_SESSION_RECURRENCE:
    st->sps_mode = SPS_MODE_PARSED_SESSION_ZONE;
    if ( type == 'z' ) return SPS_SUCCESS;

  case SPS_MODE_PARSED_SESSION_ZONE:
    st->sps_mode = SPS_MODE_PARSED_SESSION_ENCKEY;
    if ( type == 'k' ) return SPS_SUCCESS;

  case SPS_MODE_PARSED_SESSION_ENCKEY:
  case SPS_MODE_PARSED_SESSION_ATTRIBUTE:
    st->sps_mode = SPS_MODE_PARSED_SESSION_ATTRIBUTE;
    if ( type == 'a' ) {
      const char *nms, *nme, *vls, *vle;
      if ( sdp_parse_attribute(st, &nms, &nme, &vls, &vle) < 0)
        SDP_RETURN_ERROR;
      if ( st->sps_attr_fn(st->sps_user_data, nms, nme, vls, vle) < 0 )
        SDP_ERROR(SPS_INVALID_ATTR);
    } else if ( type == 'm' ) {
      if ( sdp_parse_new_media(st) < 0)
        SDP_RETURN_ERROR;
      st->sps_mode = SPS_MODE_PARSED_MEDIA_HEADER;
    } else
      SDP_ERROR(SPS_INVALID_TYPE);
    break;

  case SPS_MODE_PARSED_MEDIA_HEADER:
    st->sps_mode = SPS_MODE_PARSED_MEDIA_TITLE;
    if ( type == 'i' ) {
      char media_name[SPS_NAME_LEN];
      if ( sdp_consume_rest(st, media_name, sizeof(media_name)) < 0 )
        SDP_ERROR(SPS_NAME_TOO_LONG);

      if ( st->sps_media_ctl_fn(st->sps_user_data, SPS_MEDIA_SET_TITLE, (void *) media_name) == -1 )
        SDP_ERROR(SPS_INVALID_MEDIA_NAME);

      return SPS_SUCCESS;
    }

  case SPS_MODE_PARSED_MEDIA_TITLE:
    st->sps_mode = SPS_MODE_PARSED_MEDIA_CONNECTION;
    if ( type == 'c' ) {
      // TODO parse connection
      kite_sock_addr addr;

      if ( st->sps_media_ctl_fn(st->sps_user_data, SPS_MEDIA_SET_CONNECTION, (void *)&addr) == -1 )
        SDP_ERROR(SPS_INVALID_CONNECTION);

      return SPS_SUCCESS;
    } else if ( st->sps_flags & SPS_FLAG_GLOBAL_CONNECTION ) {
      if ( st->sps_media_ctl_fn(st->sps_user_data, SPS_MEDIA_SET_CONNECTION, (void *)&st->sps_global_connection) == -1 )
        SDP_ERROR(SPS_INVALID_CONNECTION);
    } else
      SDP_ERROR(SPS_NO_CONNECTION);
    // No break because if we have a global connection, this should fall through

  case SPS_MODE_PARSED_MEDIA_CONNECTION:
    st->sps_mode = SPS_MODE_PARSED_MEDIA_BANDWIDTH;
    if ( type == 'b' ) {
      // TODO bandwidth
      return SPS_SUCCESS;
    }

  case SPS_MODE_PARSED_MEDIA_BANDWIDTH:
    st->sps_mode = SPS_MODE_PARSED_MEDIA_ENCKEY;
    if ( type == 'k' ) {
      // TODO parse enckey
      return SPS_SUCCESS;
    }

  case SPS_MODE_PARSED_MEDIA_ENCKEY:
  case SPS_MODE_PARSED_MEDIA_ATTRIBUTE:
    st->sps_mode = SPS_MODE_PARSED_MEDIA_ATTRIBUTE;
    if ( type == 'a' ) {
      const char *nms, *nme, *vls, *vle;
      fprintf(stderr, "This is an sdp attribute\n");
      if ( sdp_parse_attribute(st, &nms, &nme, &vls, &vle) < 0 )
        SDP_RETURN_ERROR;

      fprintf(stderr, "Got sdp attribute %.*s\n", (int)(nme - nms), nms);

      if ( st->sps_attr_fn(st->sps_user_data, nms, nme, vls, vle) < 0 )
        SDP_ERROR(SPS_INVALID_ATTR);
    } else if ( type == 'm' ) {
      if ( !sdp_parse_new_media(st) )
        SDP_RETURN_ERROR;
    } else
      SDP_ERROR(SPS_INVALID_TYPE);
    break;

  default:
    if ( st->sps_mode >= 0 )
      SDP_ERROR(SPS_INVALID_STATE);
    else
      return st->sps_mode;
  }

  return SPS_SUCCESS;
}

int sdp_parse(struct sdpparsest *st, const char *buf, size_t buf_sz) {
  int i, line_pos;

  // On error, return the error
  if ( st->sps_mode < 0 ) return st->sps_mode;

  line_pos = strnlen(st->sps_line, sizeof(st->sps_line));
  if ( line_pos >= sizeof(st->sps_line) ) {
    st->sps_mode = SPS_LINE_TOO_LONG;
    return SPS_LINE_TOO_LONG;
  }

  if ( buf_sz > 0 ) {
    for ( i = 0; i < buf_sz; ++i ) {
      if ( line_pos >= (sizeof(st->sps_line) - 1) ) {
        st->sps_mode = SPS_LINE_TOO_LONG;
        return SPS_LINE_TOO_LONG;
      }

      if ( buf[i] == '\r' ) {
        if ( st->sps_line_mode == SPS_LINE_MODE_NORMAL )
          st->sps_line_mode = SPS_LINE_MODE_CARRIAGE_RETURN;
        else {
          st->sps_line_mode = SPS_INVALID_NEWLINE;
          return SPS_INVALID_NEWLINE;
        }
      } else if ( buf[i] == '\n' ) {
        st->sps_line_mode = SPS_LINE_MODE_NORMAL;

        // Do parse line
        if ( sdp_parse_line(st) < 0 )
          return st->sps_mode;

        line_pos = 0;
        st->sps_line[0] = '\0';
      } else if ( buf[i] == '\0' ) {
        st->sps_mode = SPS_INVALID_CHARACTER;
        return SPS_INVALID_CHARACTER;
      } else {
        st->sps_line[line_pos] = buf[i];
        st->sps_line[line_pos + 1] = '\0';
        line_pos++;
      }
    }
    return SPS_PARSE_MORE;
  } else {
    // TODO
    return SPS_SUCCESS;
  }
}
