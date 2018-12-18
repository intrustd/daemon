#ifndef __dns_H__
#define __dns_H__

#include "util.h"

struct dnshdr {
  uint16_t dh_id;
  uint16_t dh_flags;
  uint16_t dh_qdcount;
  uint16_t dh_ancount;
  uint16_t dh_nscount;
  uint16_t dh_arcount;
} KITE_PACKED;

struct dnsqname {
  uint16_t dqn_len;
  char     dqn_data[];
} KITE_PACKED;

struct dnsqdsuffix {
  uint16_t dqs_type;
  uint16_t dqs_class;
} KITE_PACKED;

struct dnsansuffix {
  uint16_t das_type;
  uint16_t das_class;
  uint16_t das_ttl;
  uint16_t das_rdlength;
  char     das_rdata[];
} KITE_PACKED;

#define DNS_TYPE_A    0x0001
#define DNS_TYPE_AAAA 0x001C

#define DNS_CLASS_IN  0x0001

#endif
