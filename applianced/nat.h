#ifndef __nat_H__
#define __nat_H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <uthash.h>

#include "bridge.h"

struct vlannat;

typedef void(*vlannat_on_packet)(struct vlannat *, const void *buf, size_t sz);

struct vlannat {
  UT_hash_handle vn_hh; // Based on internal address

  vlannat_on_packet vn_on_recv_pkt;
  void *vn_user_data;

  struct arpentry vn_arpentry;

  struct in_addr vn_gateway; // i.e., 172.18.0.1/24
  struct in_addr vn_internal; // i.e., 10.0.0.94
  int vn_rule_cnt;
  struct vlannatrl *vn_rules;
};

struct vlannatrl {
  struct in_addr vnr_gw_ip; // i.e., 172.18.0.2
  struct in_addr vnr_internal_ip; // i.e., 10.0.0.95
};

void vlannat_init(struct vlannat *vlan,
                  struct in_addr *gateway, struct in_addr *internal);
void vlannat_release(struct vlannat *vlan);

int vlannat_add_rule(struct vlannat *nat, struct in_addr *gw_ip,
                     struct in_addr *internal_ip);

// Returns 1 if the packet was rewritten, 0 if the packet didn't meet the rules,
// or -1 on error
int vlannat_rewrite_pkt_from_gw(struct vlannat *nat, char *pkt, size_t pkt_len,
                                struct in_addr *local_dest);
int vlannat_rewrite_pkt_to_gw(struct vlannat *nat, char *pkt, size_t pkt_len);

#endif
