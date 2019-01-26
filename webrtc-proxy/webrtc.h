#ifndef __intrustd_webrtc_H__
#define __intrustd_webrtc_H__

#include <stdint.h>

struct wrtcmsg {
  uint8_t wm_type;

  // For WEBRTC_MSG_OPEN
  uint8_t wm_ctype;
  uint16_t wm_prio;
  uint32_t wm_rel;
  uint16_t wm_lbllen;
  uint16_t wm_prolen;

  char wm_names[];
} __attribute__((packed));

#define WEBRTC_MSG_LABEL(msg) ((msg)->wm_names)
#define WEBRTC_MSG_PROTO(msg) ((msg)->wm_names + ntohs((msg)->wm_lbllen))

#define WEBRTC_MSG_OPEN_ACK 2
#define WEBRTC_MSG_OPEN     3

// For wm_ctype
#define DATA_CHANNEL_RELIABLE                          0x00
#define DATA_CHANNEL_RELIABLE_UNORDERED                0x80
#define DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT           0x01
#define DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED 0x81
#define DATA_CHANNEL_PARTIAL_RELIABLE_TIMED            0x02
#define DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED  0x82

// For SCTP PPID
#define WEBRTC_CONTROL_PPID 50
#define WEBRTC_BINARY_PPID 53
#define WEBRTC_BINARY_EMPTY_PPID 57

#endif
