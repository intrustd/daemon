#ifndef __intrustd_sdp_H__
#define __intrustd_sdp_H__

#include <sys/socket.h>
#include <sys/types.h>
#include <stdint.h>

#include "util.h"

#define SPS_NAME_LEN 65
#define SPS_LINE_LEN 512

#define SPS_MODE_START                      0
#define SPS_MODE_PARSED_SESSION_VERSION     1
#define SPS_MODE_PARSED_SESSION_ORIGINATOR  2
#define SPS_MODE_PARSED_SESSION_NAME        3
#define SPS_MODE_PARSED_SESSION_INFORMATION 4
#define SPS_MODE_PARSED_SESSION_URI         5
#define SPS_MODE_PARSED_SESSION_EMAIL       6
#define SPS_MODE_PARSED_SESSION_PHONE       7
#define SPS_MODE_PARSED_SESSION_CONNECTION  8
#define SPS_MODE_PARSED_SESSION_BANDWIDTH   9
#define SPS_MODE_PARSED_SESSION_TIME        10
#define SPS_MODE_PARSED_SESSION_RECURRENCE  11
#define SPS_MODE_PARSED_SESSION_ZONE        12
#define SPS_MODE_PARSED_SESSION_ENCKEY      13
#define SPS_MODE_PARSED_SESSION_ATTRIBUTE   14
#define SPS_MODE_PARSED_MEDIA_HEADER        15
#define SPS_MODE_PARSED_MEDIA_TITLE         16
#define SPS_MODE_PARSED_MEDIA_CONNECTION    17
#define SPS_MODE_PARSED_MEDIA_BANDWIDTH     18
#define SPS_MODE_PARSED_MEDIA_ENCKEY        19
#define SPS_MODE_PARSED_MEDIA_ATTRIBUTE     20

#define SPS_LINE_MODE_NORMAL                1
#define SPS_LINE_MODE_CARRIAGE_RETURN       2

#define SPS_MEDIA_SET_CONNECTION 1
#define SPS_MEDIA_SET_TITLE 2
#define SPS_MEDIA_SET_TYPE 3
#define SPS_MEDIA_SET_PROTOCOL 4
#define SPS_MEDIA_SET_FORMAT 5
#define SPS_MEDIA_SET_PORTS 6

typedef int(*sdpnewmediafn)(void *);
typedef int(*sdpmediactlfn)(void *, int, void *);
typedef int(*sdpattrfn)(void *, const char*, const char*, const char*, const char*);

struct sdpparsest {
  int             sps_mode;
  int             sps_line_mode;

  int             sps_line_num;
  int             sps_column_pos;

  int             sps_session_version;
  char            sps_session_name[SPS_NAME_LEN];
  char            sps_username[SPS_NAME_LEN];
  char            sps_session_id[SPS_NAME_LEN];
  intrustd_sock_addr sps_originator;
  uint32_t        sps_flags;

  uint64_t        sps_start_time, sps_end_time;

  sdpnewmediafn   sps_new_media_fn;
  sdpmediactlfn   sps_media_ctl_fn;
  sdpattrfn       sps_attr_fn;
  void           *sps_user_data;

  char            sps_media_name[SPS_NAME_LEN];
  intrustd_sock_addr sps_global_connection;

  char            sps_line[SPS_LINE_LEN + 1];
};

#define SPS_FLAG_GLOBAL_CONNECTION 0x00000001
#define SPS_FLAG_START_TIME        0x00000002
#define SPS_FLAG_END_TIME          0x00000004
#define SPS_FLAG_RECURRENCE        0x00000008

#define SPS_SUCCESS    0
#define SPS_PARSE_MORE 1
#define SPS_NAME_TOO_LONG (-1)
#define SPS_VALUE_TOO_LONG (-2)
#define SPS_INVALID_TYPE (-3)
#define SPS_INVALID_SESSION_NAME (-4)
#define SPS_INVALID_STATE (-5)
#define SPS_INVALID_ORIGINATOR (-6)
#define SPS_INVALID_NET_TYPE (-7)
#define SPS_INVALID_ADDR_TYPE (-8)
#define SPS_INVALID_ADDRESS (-9)
#define SPS_INCOMPATIBLE_VERSION (-10)
#define SPS_NO_MEDIA (-11)
#define SPS_NO_CONNECTION (-12)
#define SPS_MISSING_ATTRIBUTE_VALUE (-13)
#define SPS_MISSING_ATTRIBUTE_NAME (-14)
#define SPS_MISSING_COLON (-15)
#define SPS_LINE_TOO_LONG (-16)
#define SPS_INVALID_NEWLINE (-17)
#define SPS_INVALID_CHARACTER (-18)
#define SPS_INVALID_SESSION_VERSION (-19)
#define SPS_INVALID_CONNECTION (-20)
#define SPS_INVALID_ATTR (-21)
#define SPS_INVALID_VERSION (-22)
#define SPS_INVALID_MEDIA_NAME (-23)
#define SPS_INVALID_MEDIA (-24)
#define SPS_INVALID_MEDIA_PROTOCOL (-25)
#define SPS_INVALID_MEDIA_FORMAT (-26)
#define SPS_INVALID_MEDIA_TYPE (-27)
#define SPS_INVALID_MEDIA_PORTS (-28)

int sdp_init(struct sdpparsest *st, sdpnewmediafn new_media, sdpmediactlfn media_ctl,
             sdpattrfn attr, void *user);
// resets an initialized sdp parser
void sdp_reset(struct sdpparsest *st);

// Returns an SPS_* constant. Should be called with an empty buffer to
// signal end, and the return value checked to ensure SPS_SUCCESS.
//
// On SPS_SUCCESS, assume the entire buffer was parsed
int sdp_parse(struct sdpparsest *st, const char *buf, size_t buf_sz);

#endif
