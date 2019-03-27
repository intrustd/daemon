#include <string.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <linux/tcp.h>

#include "util.h"
#include "nat.h"

void vlannat_do_nothing(struct vlannat *nat, const void *buf, size_t sz) {
  fprintf(stderr, "Warning: vlannat_do_nothing called\n");
}

void vlannat_init(struct vlannat *vlan, struct in_addr *gw, struct in_addr *internal) {
  memcpy(&vlan->vn_gateway, gw, sizeof(vlan->vn_gateway));
  memcpy(&vlan->vn_internal, internal, sizeof(vlan->vn_internal));
  vlan->vn_rule_cnt = 0;
  vlan->vn_rules = NULL;

  vlan->vn_user_data = NULL;
  vlan->vn_on_recv_pkt = vlannat_do_nothing;

  memcpy(&vlan->vn_arpentry.ae_ip, &vlan->vn_internal, sizeof(vlan->vn_arpentry.ae_ip));
  memset(&vlan->vn_arpentry.ae_mac, 0, sizeof(vlan->vn_arpentry.ae_mac));
}

void vlannat_release(struct vlannat *vlan) {
  if ( vlan->vn_rules )
    free(vlan->vn_rules);
}

static void vlannat_lookup_gw(struct vlannat *nat, struct in_addr *gw_ip,
                              struct vlannatrl **rule) {
  int i = 0;

  *rule = NULL;

  for ( i = 0; i < nat->vn_rule_cnt; ++i ) {
    if ( memcmp(&nat->vn_rules[i].vnr_gw_ip, gw_ip, sizeof(*gw_ip)) == 0 ) {
      *rule = &nat->vn_rules[i];
      return;
    }
  }
}

static void vlannat_lookup_internal(struct vlannat *nat, struct in_addr *internal_ip,
                                    struct vlannatrl **rule) {
  int i = 0;

  *rule = NULL;

  for ( i = 0; i < nat->vn_rule_cnt; ++i ) {
    if ( memcmp(&nat->vn_rules[i].vnr_internal_ip, internal_ip, sizeof(*internal_ip)) == 0 ) {
      *rule = &nat->vn_rules[i];
      return;
    }
  }
}

int vlannat_add_rule(struct vlannat *nat, struct in_addr *gw_ip,
                     struct in_addr *internal_ip) {
  struct vlannatrl *existing_gw = NULL, *existing_internal = NULL;

  vlannat_lookup_gw(nat, gw_ip, &existing_gw);
  vlannat_lookup_internal(nat, internal_ip, &existing_internal);

  if ( !existing_gw && !existing_internal ) {
    struct vlannatrl *new_rules;

    // Add 1
    new_rules = realloc(nat->vn_rules, sizeof(*nat->vn_rules) * (nat->vn_rule_cnt + 1));
    if ( !new_rules ) return -1;

    nat->vn_rules = new_rules;
    memcpy(&new_rules[nat->vn_rule_cnt].vnr_gw_ip, gw_ip, sizeof(new_rules[nat->vn_rule_cnt].vnr_gw_ip));
    memcpy(&new_rules[nat->vn_rule_cnt].vnr_internal_ip, internal_ip, sizeof(new_rules[nat->vn_rule_cnt].vnr_internal_ip));

    nat->vn_rule_cnt ++;
  } else if ( existing_gw && !existing_internal ) {
    memcpy(&existing_gw->vnr_internal_ip, internal_ip, sizeof(existing_gw->vnr_internal_ip));
  } else if ( existing_internal && !existing_gw ) {
    memcpy(&existing_internal->vnr_gw_ip, gw_ip, sizeof(existing_internal->vnr_gw_ip));
  } else if ( existing_internal != existing_gw ) return -1;

  return 0;
}

static void recalc_cs(struct iphdr *iphdr, char *pkt, size_t pkt_len) {
  struct checksumst css;
  uint16_t contained_len, proto;

  struct tcphdr tcphdr;

  switch ( iphdr->protocol ) {
  case IPPROTO_TCP:
    if ( (pkt_len - sizeof(*iphdr)) < sizeof(tcphdr) ) {
      fprintf(stderr, "Malformed TCP header\n");
      return;
    }

    memcpy(&tcphdr, pkt + sizeof(*iphdr), sizeof(tcphdr));

    checksum_init(&css);
    checksum_update(&css, &iphdr->saddr, sizeof(iphdr->saddr));
    checksum_update(&css, &iphdr->daddr, sizeof(iphdr->daddr));
    proto = iphdr->protocol;
    proto = htons(proto);
    checksum_update(&css, &proto, sizeof(proto));

    contained_len = htons(ntohs(iphdr->tot_len) - sizeof(*iphdr));
    checksum_update(&css, &contained_len, sizeof(contained_len));

    tcphdr.check = 0;
    checksum_update(&css, &tcphdr, sizeof(tcphdr));

    checksum_update(&css, pkt + sizeof(*iphdr) + sizeof(tcphdr),
                    pkt_len - sizeof(*iphdr) - sizeof(tcphdr));

    tcphdr.check = htons(checksum_finish(&css));
    memcpy(pkt + sizeof(*iphdr), &tcphdr, sizeof(tcphdr));

    break;

  case IPPROTO_UDP:
    break;

  default:
    fprintf(stderr, "Unknown IP protocol: checksum unchanged: %d\n", iphdr->protocol);
    break;
  }
}

int vlannat_rewrite_pkt_from_gw(struct vlannat *nat, char *pkt, size_t pkt_len,
                                struct in_addr *local_dest) {

  struct vlannatrl *rl;
  struct iphdr iphdr;
  struct in_addr gw_dst;
  uint16_t cs;

  if ( pkt_len < sizeof(iphdr) ) { fprintf(stderr, "vlan: not an IP pkt\n"); return 0; }

  memcpy(&iphdr, pkt, sizeof(iphdr));

  cs = ntohs(iphdr.check);
  iphdr.check = 0;
  if ( cs != ip_checksum(&iphdr, sizeof(iphdr)) )
    return 0;

  // Since it's from the gateway, ensure it matches the gateway IP, else drop
  if ( iphdr.saddr != nat->vn_gateway.s_addr ) {
    char ip1[INET6_ADDRSTRLEN], ip2[INET6_ADDRSTRLEN];
    fprintf(stderr, "Source addr mismatch: %s %s\n",
            inet_ntop(AF_INET, &iphdr.saddr, ip1, sizeof(ip1)),
            inet_ntop(AF_INET, &nat->vn_gateway.s_addr, ip2, sizeof(ip2)));
    return 0;
  }

  // Translate src address
  iphdr.saddr = nat->vn_internal.s_addr;

  // Now attempt to find the destination
  gw_dst.s_addr = iphdr.daddr;
  vlannat_lookup_gw(nat, &gw_dst, &rl);
  if ( !rl ) return 0;

  iphdr.daddr = rl->vnr_internal_ip.s_addr;

  iphdr.check = htons(ip_checksum(&iphdr, sizeof(iphdr)));
  memcpy(pkt, &iphdr, sizeof(iphdr));

  if ( local_dest )
    memcpy(local_dest, &rl->vnr_internal_ip, sizeof(*local_dest));

  recalc_cs(&iphdr, pkt, pkt_len);

  return 1;
}

int vlannat_rewrite_pkt_to_gw(struct vlannat *nat, char *pkt, size_t pkt_len) {

  struct vlannatrl *rl;
  struct iphdr iphdr;
  struct in_addr int_src;
  uint16_t cs;

  if ( pkt_len < sizeof(iphdr) ) { fprintf(stderr, "vlan: not an IP pkt\n"); return 0; }

  memcpy(&iphdr, pkt, sizeof(iphdr));

  cs = ntohs(iphdr.check);
  iphdr.check = 0;
  if ( cs != ip_checksum(&iphdr, sizeof(iphdr)) )
    return 0;

  // Since it's to the gateway, ensure it matches the internal IP, else drop
  if ( iphdr.daddr != nat->vn_internal.s_addr ) {
    char ip1[INET6_ADDRSTRLEN], ip2[INET6_ADDRSTRLEN];
    fprintf(stderr, "Source addr mismatch: %s %s\n",
            inet_ntop(AF_INET, &iphdr.saddr, ip1, sizeof(ip1)),
            inet_ntop(AF_INET, &nat->vn_gateway.s_addr, ip2, sizeof(ip2)));
    return 0;
  }

  // Translate dst address
  iphdr.daddr = nat->vn_gateway.s_addr;

  // Now attempt to find the source
  int_src.s_addr = iphdr.saddr;
  vlannat_lookup_internal(nat, &int_src, &rl);
  if ( !rl ) return 0;

  iphdr.saddr = rl->vnr_gw_ip.s_addr;

  iphdr.check = htons(ip_checksum(&iphdr, sizeof(iphdr)));
  memcpy(pkt, &iphdr, sizeof(iphdr));

  recalc_cs(&iphdr, pkt, pkt_len);

  return 1;
}
