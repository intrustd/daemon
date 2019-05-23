#define _GNU_SOURCE
#include <openssl/err.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <net/if.h>
#define flock __flock
#include <fcntl.h>
#undef flock
#include <sched.h>
#include <sys/uio.h>
#include <linux/sched.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/syscall.h>

#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

#include "bridge.h"
#include "container.h"
#include "util.h"
#include "persona.h"
#include "application.h"
#include "state.h"
#include "intrustd_proto.h"
#include "nat.h"

#define APPLIANCED_APP_PORT 9998
#define INET_LINK_NAME "intrustd-inet"

#define INTERNET_GATEWAY "10.254.254.254"

#define BRIDGE_STACK_SIZE (2 * 1024 * 1024)

#define OP_BRIDGE_TAP_PACKETS EVT_CTL_CUSTOM
#define OP_BRIDGE_BPR_FINISHED (EVT_CTL_CUSTOM + 1)

#define OP_BRTUNNEL_INIT EVT_CTL_CUSTOM

struct brctlmsg {
  uint16_t bcm_what;
};

struct brctlrsp {
  int bcr_sts;
};

struct brctlmsg_setupns {
  struct brctlmsg bcm_msg;
  int bcm_port_ix;
  struct in_addr bcm_ip;
};

struct brctlmsg_newtun {
  struct brctlmsg bcm_msg;
  int bcm_ports[2];
};

struct brctlmsg_deltun {
  struct brctlmsg bcm_msg;
  int bcm_ports[2];
};

struct brctlmsg_delport {
  struct brctlmsg bcm_msg;
  int bcm_port;
  struct arpentry bcm_arp;
};

struct brctlmsg_markadmin {
  struct brctlmsg bcm_msg;
  int bcm_port;
  struct arpentry bcm_arp;
};

struct brctlrsp_markadmin {
  struct brctlrsp bcr_rsp;
  struct in_addr bcr_inet_gw;
};

#define BR_SETUP_NAMESPACE 1
#define BR_NEW_TUNNEL      2
#define BR_DEL_TUNNEL      3
#define BR_DISCONNECT_PORT 4
#define BR_MARK_AS_ADMIN   5

static int bridge_setup_ns(struct brstate *br);
static int bridge_setup_main(void *br_ptr);
static int bridge_create_veth_to_ns(struct brstate *br, int port_ix, int this_netns, struct in_addr *this_ip);
static int setup_namespace(struct brstate *br, pid_t new_proc,
                           int port_ix, struct in_addr *this_ip);

//static int bridge_enter_network_namespace(struct brstate *br);
//static int bridge_enter_user_namespace(struct brstate *br);
static int bridge_move_if_to_ns(struct brstate *br, const char *if_name, int netns);
static int bridge_create_veth(struct brstate *br, const char *in_if_name, const char *out_if_name, int set_in_master);
static int bridge_remove_ebtable_spoof(struct brstate *br, int port, struct arpentry *arp);
static int bridge_remove_ebtable_sub(struct brstate *br, int port);
static int bridge_delete_veth(struct brstate *br, const char *if_name);
static int bridge_disconnect_iface(struct brstate *brb, const char *if_name);
static void bridge_handle_bpr_response(struct brstate *br, struct brpermrequest *bpr);
static int bridge_try_nat(struct brstate *br, struct eventloop *el, int sz,
                          struct ethhdr *eth, struct iphdr *ip);
static int find_hw_addr(const char *if_name, unsigned char *mac_addr);
static void bridgefn(struct eventloop *el, int op, void *arg);

static pid_t g_main_pid = -1;

void bridge_clear(struct brstate *br) {
  br->br_mutexes_initialized = 0;
  br->br_appstate = NULL;
  br->br_iproute_path = NULL;
  br->br_ebroute_path = NULL;
  br->br_euid = 0;
  br->br_uid = br->br_user_uid = br->br_daemon_uid = 0;
  br->br_gid = br->br_user_gid = br->br_daemon_uid = 0;
  br->br_comm_fd[0] = br->br_comm_fd[1] = 0;
  br->br_debug_out = NULL;
  br->br_tapfd = 0;
  br->br_bridge_addr.s_addr = 0;
  br->br_tap_addr.s_addr = 0;
  br->br_arp_table = NULL;
  br->br_sctp_table = NULL;
  br->br_nat_table = NULL;
  memset(&br->br_tap_mac, 0, sizeof(mac_addr));
  fdsub_clear(&br->br_tap_sub);
  br->br_next_ip = 0x0A000001;
  br->br_eth_ix = 0;
  br->br_tunnels = NULL;
}

int bridge_init(struct brstate *br, struct appstate *as, uid_t euid,
                uid_t user_uid, gid_t user_gid,
                uid_t daemon_uid, gid_t daemon_gid,
                const char *iproute, const char *ebroute) {
  char ip_dbg[INET_ADDRSTRLEN], tap_ip_dbg[INET_ADDRSTRLEN], mac_dbg[32];
  int err;

  bridge_clear(br);

  br->br_appstate = as;
  br->br_euid = euid;
  if ( euid == 0 ) {
    br->br_uid = br->br_gid = 0;
  } else {
    br->br_uid = getuid();
    br->br_gid = getgid();
  }
  br->br_user_uid = user_uid;
  br->br_user_gid = user_gid;
  br->br_daemon_uid = daemon_uid;
  br->br_daemon_gid = daemon_gid;

  bridge_allocate_ip(br, &br->br_bridge_addr);
  br->br_tap_addr.s_addr = br->br_bridge_addr.s_addr;
  bridge_allocate_ip(br, &br->br_tap_addr);
  random_mac(br->br_tap_mac);

  fprintf(stderr, "Opening bridge with IP address %s (Tap Mac %s and IP %s)\n",
          inet_ntop(AF_INET, &br->br_bridge_addr, ip_dbg, sizeof(ip_dbg)),
          mac_ntop(br->br_tap_mac, mac_dbg, sizeof(mac_dbg)),
          inet_ntop(AF_INET, &br->br_tap_addr, tap_ip_dbg, sizeof(tap_ip_dbg)));

  br->br_iproute_path = iproute;
  br->br_ebroute_path = ebroute;

  err = pthread_rwlock_init(&br->br_arp_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "Could not initialize arp mutex: %s\n", strerror(err));
    goto error;
  }
  br->br_mutexes_initialized |= BR_ARP_MUTEX_INITIALIZED;

  err = pthread_rwlock_init(&br->br_sctp_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "Could not initialize sctp mutex: %s\n", strerror(err));
    goto error;
  }
  br->br_mutexes_initialized |= BR_SCTP_MUTEX_INITIALIZED;

  err = pthread_mutex_init(&br->br_tap_write_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "Could not initialize tap write mutex: %s\n", strerror(err));
    goto error;
  }
  br->br_mutexes_initialized |= BR_TAP_MUTEX_INITIALIZED;

  err = pthread_mutex_init(&br->br_tunnel_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "Could not initialized tunnel mutex: %s\n", strerror(err));
    goto error;
  }
  br->br_mutexes_initialized |= BR_TUNNEL_MUTEX_INITIALIZED;

  err = pthread_mutex_init(&br->br_comm_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "Could not initialize comm mutex: %s\n", strerror(err));
    goto error;
  }
  br->br_mutexes_initialized |= BR_COMM_MUTEX_INITIALIZED;

  if ( bridge_setup_ns(br) < 0 ) {
    fprintf(stderr, "bridge_init: bridge_setup_ns failed\n");
    goto error;
  }

  return 0;

 error:
  bridge_release(br);
  return -1;
}

void bridge_release(struct brstate *br) {
  if ( br->br_mutexes_initialized & BR_DEBUG_MUTEX_INITIALIZED )
    pthread_mutex_lock(&br->br_debug_mutex);

  if ( br->br_debug_out ) {
    fclose(br->br_debug_out);
    br->br_debug_out = NULL;
  }

  if ( br->br_mutexes_initialized & BR_DEBUG_MUTEX_INITIALIZED ) {
    pthread_mutex_unlock(&br->br_debug_mutex);
    pthread_mutex_destroy(&br->br_debug_mutex);
    br->br_mutexes_initialized &= ~BR_DEBUG_MUTEX_INITIALIZED;
  }

  if ( br->br_mutexes_initialized & BR_ARP_MUTEX_INITIALIZED ) {
    pthread_rwlock_destroy(&br->br_arp_mutex);
    br->br_mutexes_initialized &= ~BR_ARP_MUTEX_INITIALIZED;
  }

  if ( br->br_mutexes_initialized & BR_SCTP_MUTEX_INITIALIZED ) {
    pthread_rwlock_destroy(&br->br_sctp_mutex);
    br->br_mutexes_initialized &= ~BR_SCTP_MUTEX_INITIALIZED;
  }

  if ( br->br_mutexes_initialized & BR_TAP_MUTEX_INITIALIZED ) {
    pthread_mutex_destroy(&br->br_tap_write_mutex);
    br->br_mutexes_initialized &= ~BR_TAP_MUTEX_INITIALIZED;
  }

  if ( br->br_mutexes_initialized & BR_TUNNEL_MUTEX_INITIALIZED ) {
    pthread_mutex_destroy(&br->br_tunnel_mutex);
    br->br_mutexes_initialized &= ~BR_TUNNEL_MUTEX_INITIALIZED;
  }

  if ( br->br_mutexes_initialized & BR_COMM_MUTEX_INITIALIZED ) {
    pthread_mutex_destroy(&br->br_comm_mutex);
    br->br_mutexes_initialized &= ~BR_COMM_MUTEX_INITIALIZED;
  }

  if ( br->br_tapfd ) {
    close(br->br_tapfd);
    br->br_tapfd = 0;
  }

  if ( br->br_comm_fd[0] ) {
    close(br->br_comm_fd[0]);
    br->br_comm_fd[0] = 0;
  }

  if ( br->br_comm_fd[1] ) {
    close(br->br_comm_fd[1]);
    br->br_comm_fd[1] = 0;
  }

  // TODO free hash
}

static void log_tap_packet(FILE *out, char dir, const struct iovec *iov, int iovcnt) {
  int iov_ix;
  size_t i;
  struct tm cur_time;
  time_t now;

  time(&now);
  localtime_r(&now, &cur_time);

  fprintf(out, "%c %02d:%02d:%02d.000000 0000", dir, cur_time.tm_hour, cur_time.tm_min, cur_time.tm_sec);
  for ( iov_ix = 0; iov_ix < iovcnt; ++iov_ix ) {
    for ( i = 0; i < iov[iov_ix].iov_len; ++i )
      fprintf(out, " %02x", ((const unsigned char *)iov[iov_ix].iov_base)[i]);
  }
  fprintf(out, "\n");
  fflush(out);
}

static void bridge_process_arp(struct brstate *br, int size) {
  struct arphdr hdr;
  uint16_t ether_type;

  if ( size < (sizeof(struct ethhdr) + sizeof(struct arphdr)) ) {
    fprintf(stderr, "bridge_process_arp: not enough space in packet\n");
    return;
  }

  memcpy(&hdr, br->br_tap_pkt + sizeof(struct ethhdr), sizeof(hdr));

  if ( ntohs(hdr.ar_hrd) != ARPHRD_ETHER ) {
    fprintf(stderr, "bridge_process_arp: dropping ARP of type %04x\n", htons(hdr.ar_hrd));
    return;
  }

  ether_type = ntohs(hdr.ar_pro);
  if ( hdr.ar_hln != ETH_ALEN ||
       (ether_type == ETH_P_IP && hdr.ar_pln != 4) ||
       (ether_type == ETH_P_IPV6 && hdr.ar_pln != 16) ) {
    fprintf(stderr, "bridge_process_arp: drop packet due to addr length mismatch\n");
    return;
  }

  switch ( ntohs(hdr.ar_op) ) {
  case ARPOP_REQUEST:
    if ( ether_type == ETH_P_IP ) {
      struct in_addr which_ip;
      struct ethhdr rsp_eth;
      struct arphdr rsp_arp;
      uint32_t src_hw_ip;
      mac_addr src_hw_addr;
      int was_found = 0;

      memset(rsp_eth.h_dest, 0xFF, ETH_ALEN);
      rsp_eth.h_proto = htons(ETH_P_ARP);

      rsp_arp.ar_hrd = htons(ARPHRD_ETHER);
      rsp_arp.ar_pro = htons(ETH_P_IP);
      rsp_arp.ar_hln = ETH_ALEN;
      rsp_arp.ar_pln = 4;
      rsp_arp.ar_op = htons(ARPOP_REPLY);

      if ( size < (sizeof(struct ethhdr) + sizeof(struct arphdr) +
                   (2 * hdr.ar_hln) + hdr.ar_pln) ) {
        fprintf(stderr, "bridge_process_arp: packet is too small\n");
        return;
      }

      memcpy(&which_ip.s_addr, br->br_tap_pkt + sizeof(struct ethhdr) +
             sizeof(struct arphdr) + (2 * hdr.ar_hln) + hdr.ar_pln, sizeof(which_ip.s_addr));

      if ( memcmp(&which_ip, &br->br_tap_addr, sizeof(which_ip)) == 0 ) {
        was_found = 1;
        memcpy(rsp_eth.h_source, br->br_tap_mac, ETH_ALEN);
        memcpy(src_hw_addr, br->br_tap_mac, ETH_ALEN);
        src_hw_ip = br->br_tap_addr.s_addr;
      } else {
        if ( pthread_rwlock_rdlock(&br->br_arp_mutex) == 0 ) {
          struct arpentry *found;
          HASH_FIND(ae_hh, br->br_arp_table, &which_ip, sizeof(which_ip), found);
          if ( found ) {
            was_found = 1;
            memcpy(rsp_eth.h_source, br->br_tap_mac, ETH_ALEN);
            memcpy(src_hw_addr, found->ae_mac, ETH_ALEN);
            src_hw_ip = found->ae_ip.s_addr;
          }
          pthread_rwlock_unlock(&br->br_arp_mutex);
        } else
          fprintf(stderr, "bridge_process_arp: could not lock arp table\n");
      }

      if ( was_found ) {
        mac_addr tgt_hw_addr = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        struct iovec iov[] = {
          { .iov_base = &rsp_eth, .iov_len = sizeof(rsp_eth) },
          { .iov_base = &rsp_arp, .iov_len = sizeof(rsp_arp) },
          { .iov_base = src_hw_addr, .iov_len = sizeof(src_hw_addr) },
          { .iov_base = &src_hw_ip, .iov_len = sizeof(src_hw_ip) },
          { .iov_base = tgt_hw_addr, .iov_len = sizeof(tgt_hw_addr) },
          { .iov_base = br->br_tap_pkt + sizeof(struct ethhdr) + sizeof(struct arphdr) + hdr.ar_pln,
            .iov_len = sizeof(uint32_t) }
        };

        bridge_write_tap_pktv(br, iov, sizeof(iov) / sizeof(iov[0]));
      } else
        fprintf(stderr, "bridge_process_arp: not found\n");
    } else
      fprintf(stderr, "bridge_process_arp: TODO IPV6\n");
    break;

  case ARPOP_REPLY:
    fprintf(stderr, "bridge_process_arp: got ARP response\n");
    break;

  default:
    fprintf(stderr, "bridge_process_arp: unknown op %04x\n", ntohs(hdr.ar_op));
    break;
  }
}

static void bridge_process_udp(struct brstate *br, struct eventloop *el, int sz,
                               struct ethhdr *hdr_eth,
                               struct iphdr *hdr_ip) {
  struct udphdr hdr_udp;
  unsigned char *buf = br->br_tap_pkt;
  if ( hdr_ip->daddr == br->br_tap_addr.s_addr &&
       memcmp(hdr_eth->h_dest, br->br_tap_mac, ETH_ALEN) == 0 ) {

    sz -= sizeof(struct ethhdr) + sizeof(struct iphdr);
    if ( sz < sizeof(hdr_udp) ) {
      fprintf(stderr, "bridge_process_udp: not enough data in udp packet\n");
      return;
    }

    buf += sizeof(struct ethhdr) + sizeof(struct iphdr);
    memcpy(&hdr_udp, buf, sizeof(hdr_udp));

    sz -= sizeof(hdr_udp);
    buf += sizeof(hdr_udp);

    switch ( ntohs(hdr_udp.uh_dport) ) {
    case APPLIANCED_APP_PORT:
      if ( sz < 4 ) {
        fprintf(stderr, "bridge_process_udp: not enough bytes in open app request\n");
        return;
      } else {
        uint32_t app_name_len;

        memcpy(&app_name_len, buf, sizeof(app_name_len));
        sz -= 4;
        buf += 4;

        app_name_len = ntohl(app_name_len);
        if ( app_name_len > APP_URL_MAX ) {
          fprintf(stderr, "bridge_process_udp: the application name is too long (%u)\n", app_name_len);
          return;
        }

        if ( sz < app_name_len ) {
          fprintf(stderr, "bridge_process_udp: the application name of length %u is too long (have %d bytes left)\n", app_name_len, sz);
          return;
        }

        fprintf(stderr, "bridge_process_udp: request to open app %.*s\n", app_name_len, buf);

        if ( pthread_rwlock_wrlock(&br->br_arp_mutex) == 0 ) {
          struct arpentry *arp;

          HASH_FIND(ae_hh, br->br_arp_table, &hdr_ip->saddr, sizeof(hdr_ip->saddr), arp);
          if ( arp && arp->ae_ctlfn ) {
            struct brpermrequest *bpr = malloc(sizeof(*bpr) + app_name_len);
            if ( !bpr ) {
              fprintf(stderr, "bridge_process_udp: could not allocate bpr request\n");
              return;
            }
            bpr->bpr_el = el;
            bpr->bpr_bridge = br;
            bpr->bpr_user_data = NULL;
            bpr->bpr_persona = NULL;
            memcpy(bpr->bpr_srchost, hdr_eth->h_source, sizeof(bpr->bpr_srchost));
            bpr->bpr_srcaddr.sin_addr.s_addr = hdr_ip->saddr;
            bpr->bpr_srcaddr.sin_port = hdr_udp.uh_sport;
            bpr->bpr_sts = BPR_ERR_INTERNAL;
            bpr->bpr_perm_size = app_name_len;
            bpr->bpr_perm.bp_type = BR_PERM_APPLICATION;
            memcpy(bpr->bpr_perm.bp_data, buf, app_name_len);
            qdevtsub_init(&bpr->bpr_finished_event, OP_BRIDGE_BPR_FINISHED, bridgefn);
            arp->ae_ctlfn(arp, ARP_ENTRY_CHECK_PERMISSION, bpr, sizeof(*bpr) + app_name_len);
          }
          pthread_rwlock_unlock(&br->br_arp_mutex);
        }
      }
      break;

    default:
      fprintf(stderr, "bridge_process_udp: unrecognized message on port %d\n", ntohs(hdr_udp.uh_dport));
      break;
    }
  }
}

static int bridge_validate_ip(struct brstate *br, struct ethhdr *hdr_eth,
                              struct iphdr *hdr_ip) {
  struct arpentry *arp;
  // Verify that this IP packet was not injected
  if ( pthread_rwlock_rdlock(&br->br_arp_mutex) == 0 ) {
    HASH_FIND(ae_hh, br->br_arp_table, &hdr_ip->saddr, sizeof(hdr_ip->saddr), arp);
    pthread_rwlock_unlock(&br->br_arp_mutex);
  } else return -1;

  if ( !arp ) {
    fprintf(stderr, "bridge_validate_ip: no entry for this IP\n");
    return -1;
  }

  if ( memcmp(hdr_eth->h_source, arp->ae_mac, ETH_ALEN) != 0 ) {
    fprintf(stderr, "bridge_validate_ip: IP/MAC mismatch\n");
    return -1;
  }

  return 0;
}

static void bridge_process_ip(struct brstate *br, struct eventloop *el, int sz) {
  struct iphdr hdr_ip;
  struct ethhdr hdr_eth;

  if ( sz < (sizeof(struct ethhdr) + sizeof(struct iphdr)) ) {
    fprintf(stderr, "bridge_process_ip: packet too small\n");
    return;
  }

  memcpy(&hdr_eth, br->br_tap_pkt, sizeof(struct ethhdr));
  memcpy(&hdr_ip, br->br_tap_pkt + sizeof(struct ethhdr), sizeof(struct iphdr));

  if ( memcmp(hdr_eth.h_dest, br->br_tap_mac, ETH_ALEN) == 0 ) {

    if ( hdr_ip.daddr == br->br_tap_addr.s_addr ) {
      if ( bridge_validate_ip(br, &hdr_eth, &hdr_ip) < 0 ) {
        fprintf(stderr, "bridge_process_ip: invalid source MAC/IP pair\n");
        return;
      }

      switch ( hdr_ip.protocol ) {
      case IPPROTO_ICMP: {
        struct icmphdr icmp;
        struct ethhdr rsp_eth;
        struct iphdr rsp_ip;
        struct icmphdr rsp_icmp;

        if ( sz < (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr)) ) {
          fprintf(stderr, "bridge_process_ip: not enough bytes (ICMP)\n");
          return;
        }

        memcpy(&icmp, br->br_tap_pkt + sizeof(struct ethhdr) + sizeof(struct iphdr),
               sizeof(icmp));
        memcpy(rsp_eth.h_dest, hdr_eth.h_source, ETH_ALEN);
        memcpy(rsp_eth.h_source, br->br_tap_mac, ETH_ALEN);
        rsp_eth.h_proto = htons(ETH_P_IP);

        rsp_ip.version = 4;
        rsp_ip.ihl = 5;
        rsp_ip.tos = 0x00;
        rsp_ip.tot_len = sz - sizeof(rsp_eth);
        rsp_ip.tot_len = 2 * ((rsp_ip.tot_len + 1) / 2);
        rsp_ip.tot_len = htons(rsp_ip.tot_len);
        rsp_ip.id = hdr_ip.id;
        rsp_ip.frag_off = htons(IP_DF);
        rsp_ip.ttl = 64;
        rsp_ip.protocol = IPPROTO_ICMP;
        rsp_ip.check = 0;
        rsp_ip.saddr = br->br_tap_addr.s_addr;
        rsp_ip.daddr = hdr_ip.saddr;
        rsp_icmp.type = ICMP_ECHOREPLY;
        rsp_icmp.code = 0;
        rsp_icmp.checksum = 0;
        rsp_icmp.un.echo.id = icmp.un.echo.id;
        rsp_icmp.un.echo.sequence = icmp.un.echo.sequence;

        rsp_ip.check = htons(ip_checksum(&rsp_ip, sizeof(rsp_ip)));
        rsp_icmp.checksum = htons(ip_checksum(&rsp_icmp, sizeof(rsp_icmp)));

        switch ( icmp.type ) {
        case ICMP_ECHO: {
          struct iovec iov[] = {
            { .iov_base = &rsp_eth, .iov_len = sizeof(rsp_eth) },
            { .iov_base = &rsp_ip, .iov_len = sizeof(rsp_ip) },
            { .iov_base = &rsp_icmp, .iov_len = sizeof(rsp_icmp) },
            { .iov_base = br->br_tap_pkt + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr),
              .iov_len = sz - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct icmphdr) }
          };
          bridge_write_tap_pktv(br, iov, sizeof(iov) / sizeof(iov[0]));
          break;
        }

        case ICMP_ECHOREPLY:
          fprintf(stderr, "bridge_process_ip: got ICMP echo reply\n");
          break;

        default:
          fprintf(stderr, "bridge_process_ip: unrecognized ICMP message %02x\n", icmp.type);
          break;
        }

        break;
      }

      case IPPROTO_SCTP:
        //      fprintf(stderr, "bridge_process_ip: got SCTP message\n");
        if ( sz < (sizeof(struct ethhdr) + sizeof(struct iphdr) + 2) ) {
          fprintf(stderr, "bridge_process_ip: SCTP packet is too short\n");
        } else {
          if ( pthread_rwlock_rdlock(&br->br_sctp_mutex) == 0 ) {
            struct sctpentry *se;
            struct sockaddr_in source;

            memset(&source, 0, sizeof(source));
            source.sin_addr.s_addr = hdr_ip.saddr;
            memcpy(&source.sin_port,
                   br->br_tap_pkt + sizeof(struct ethhdr) + sizeof(struct iphdr),
                   2);

            HASH_FIND(se_hh, br->br_sctp_table, &source, sizeof(source), se);
            if ( se ) {
              se->se_on_packet(se, br->br_tap_pkt + sizeof(struct ethhdr) + sizeof(struct iphdr),
                               sz - sizeof(struct ethhdr) - sizeof(struct iphdr));
            }
            pthread_rwlock_unlock(&br->br_sctp_mutex);
          } else
            fprintf(stderr, "bridge_process_ip: drop SCTP packet because we could not acquire lock\n");
        }
        break;

      case IPPROTO_UDP:
        bridge_process_udp(br, el, sz, &hdr_eth, &hdr_ip);
        break;

      default:
        fprintf(stderr, "bridge_process_ip: got Unknown packet %02x\n", hdr_ip.protocol);
        break;
      }
    } else {
      bridge_try_nat(br, el, sz, &hdr_eth, &hdr_ip);
    }
  }
//  else {
//    char inet_buf[INET_ADDRSTRLEN];
//    fprintf(stderr, "bridge_process_ip: Received IP packet somewhere else: %s\n",
//            inet_ntop(AF_INET, &hdr_ip.daddr, inet_buf, sizeof(inet_buf)));
//  }
}

 static void bridge_process_tap_packet(struct brstate *br, struct eventloop *el, int size) {
  // Check the contained protocol type
  struct ethhdr *pkt = (struct ethhdr *)br->br_tap_pkt;
  uint16_t ether_type = ntohs(pkt->h_proto);

  switch ( ether_type ) {
  case ETH_P_ARP:
    bridge_process_arp(br, size);
    break;
  case ETH_P_IP:
    bridge_process_ip(br, el, size);
    break;
  case ETH_P_IPV6:
    break;
  default:
    fprintf(stderr, "Dropping ethernet packet with type %d", ether_type);
    break;
  }
}

static void bridgefn(struct eventloop *el, int op, void *arg) {
  struct brpermrequest *bpr;
  struct brstate *br;
  struct fdevent *fdev;
  struct qdevent *qde;
  int err;

  switch ( op ) {
  case OP_BRIDGE_TAP_PACKETS:
    fdev = (struct fdevent *) arg;
    br = STRUCT_FROM_BASE(struct brstate, br_tap_sub, fdev->fde_sub);

    if ( FD_READ_PENDING(fdev) ) {
      err = read(br->br_tapfd, br->br_tap_pkt, sizeof(br->br_tap_pkt));
      if ( err < 0 ) {
        perror("bridge_tap_fn: read");
        eventloop_subscribe_fd(el, br->br_tapfd, FD_SUB_READ, &br->br_tap_sub);
        return;
      }

      // Attempt to process this packet
      if ( br->br_debug_out ) {
        if ( pthread_mutex_lock(&br->br_debug_mutex) == 0 ) {
          struct iovec iov = { .iov_base = br->br_tap_pkt,
                               .iov_len = err };
          log_tap_packet(br->br_debug_out, 'I', &iov, 1);
          pthread_mutex_unlock(&br->br_debug_mutex);
        } else
          fprintf(stderr, "Could not log tap packet: could not lock mutex\n");
      }

      bridge_process_tap_packet(br, el, err);
    }

    eventloop_subscribe_fd(el, br->br_tapfd, FD_SUB_READ, &br->br_tap_sub);
    break;

  case OP_BRIDGE_BPR_FINISHED:
    qde = arg;
    bpr = STRUCT_FROM_BASE(struct brpermrequest, bpr_finished_event, qde->qde_sub);
    br = bpr->bpr_bridge;
    bridge_handle_bpr_response(br, bpr);
    break;

  default:
    fprintf(stderr, "bridge_tap_fn: Unknown op %d\n", op);
  };
}

void bridge_start(struct brstate *br, struct eventloop *el) {
  fdsub_init(&br->br_tap_sub, el, br->br_tapfd, OP_BRIDGE_TAP_PACKETS, bridgefn);

  eventloop_subscribe_fd(el, br->br_tapfd, FD_SUB_READ, &br->br_tap_sub);
}

int bridge_write_tap_pktv(struct brstate *br, const struct iovec *iov, int iovcnt) {
  int err;

  if ( iovcnt < 0 ) {
    errno = EINVAL;
    return -1;
  }

  // TODO this may not be necessary
  if ( pthread_mutex_lock(&br->br_tap_write_mutex) != 0 ) {
    errno = EBUSY;
    return -1;
  }

  err = writev(br->br_tapfd, iov, iovcnt);
  if ( err < 0 ) {
    int old_err = errno;
    perror("bridge_write_tap_pkt: write");
    err = old_err;
  }

  if ( err > 0 && br->br_debug_out ) {
    if ( pthread_mutex_lock(&br->br_debug_mutex) == 0 ) {
      // Output raw tap pkt
      log_tap_packet(br->br_debug_out, 'O', iov, iovcnt);
      pthread_mutex_unlock(&br->br_debug_mutex);
    } else
      fprintf(stderr, "bridge_write_tap_pkt: Skipping debug packet because the mutex could not be locked\n");
  } else if ( err <= 0 )
    fprintf(stderr, "bridge_write_tap_pkt: Skipping packet because there was an error writing\n");

  pthread_mutex_unlock(&br->br_tap_write_mutex);

  if ( err != 0 ) {
    errno = err;
    return -1;
  } else return 0;
}

int bridge_write_tap_pkt(struct brstate *br, const unsigned char *pkt, uint16_t pkt_sz) {
  const struct iovec iov[] = {
    { .iov_base = (void *)pkt,
      .iov_len = pkt_sz }
  };

  return bridge_write_tap_pktv(br, iov, 1);
}

int bridge_write_ip_pkt_from_bridge(struct brstate *br, struct in_addr *dst,
                                    const unsigned char *tap_pkt, uint16_t tap_sz) {
  struct arpentry *arp;
  struct ethhdr mac;

  struct iovec iov[2] = {
    { .iov_base = &mac, .iov_len = sizeof(mac) },
    { .iov_base = (void *) tap_pkt, .iov_len = tap_sz }
  };

  if ( pthread_rwlock_rdlock(&br->br_arp_mutex) == 0 ) {
    HASH_FIND(ae_hh, br->br_arp_table, dst, sizeof(*dst), arp);
    pthread_rwlock_unlock(&br->br_arp_mutex);
  } else return -1;

  if ( !arp ) {
    fprintf(stderr, "bridge_write_ip_pkt_from_bridge: no entry for dest\n");
    return -1;
  }

  memcpy(mac.h_dest, arp->ae_mac, ETH_ALEN);
  memcpy(mac.h_source, br->br_tap_mac, ETH_ALEN);
  mac.h_proto = htons(ETH_P_IP);

  return bridge_write_tap_pktv(br, iov, 2);
}

int bridge_write_from_foreign_pkt(struct brstate *br, struct container *dst,
                                  const struct sockaddr *sa, socklen_t sa_sz,
                                  const unsigned char *tap_pkt, uint16_t tap_sz) {
  struct arpentry *arp;
  struct ethhdr mac;
  struct iphdr ip;

  struct sockaddr_in *sin;

  struct iovec iov[3] = {
    { .iov_base = &mac, .iov_len = sizeof(mac) },
    { 0 },
    { .iov_base = (void *) tap_pkt, .iov_len = tap_sz }
  };

  if ( pthread_rwlock_rdlock(&br->br_arp_mutex) == 0 ) {
    HASH_FIND(ae_hh, br->br_arp_table, &dst->c_ip, sizeof(dst->c_ip), arp);
    pthread_rwlock_unlock(&br->br_arp_mutex);
  } else return -1;

  if ( !arp ) {
    fprintf(stderr, "bridge_write_from_foreign_pkt: could not arp\n");
    return -1;
  }

  memcpy(mac.h_dest, arp->ae_mac, ETH_ALEN);
  memcpy(mac.h_source, br->br_tap_mac, ETH_ALEN);
  mac.h_proto = htons(ETH_P_IP);

  switch ( sa->sa_family ) {
  case AF_INET:
    sin = (struct sockaddr_in *) sa;
    if ( sa_sz < sizeof(*sin) )
      return -1;

    ip.version = 4;
    ip.ihl = 5;
    ip.tos = 0;
    ip.tot_len = htons(tap_sz + sizeof(ip));
    ip.id = 0xBEEF;
    ip.frag_off = htons(IP_DF);
    ip.ttl = 64;
    ip.protocol = IPPROTO_SCTP;
    ip.check = 0;
    ip.saddr = br->br_tap_addr.s_addr; //sin->sin_addr.s_addr;
    ip.daddr = arp->ae_ip.s_addr;

    ip.check = htons(ip_checksum(&ip, sizeof(ip)));

    iov[1].iov_base = &ip;
    iov[1].iov_len = sizeof(ip);

    return bridge_write_tap_pktv(br, iov, 3);

  default:
    fprintf(stderr, "bridge_write_from_foreign_pkt: unknown family %d\n", sa->sa_family);
    return -1;
  }
}

void bridge_enable_debug(struct brstate *br, const char *pkts_out) {
  int err;

  if ( br->br_debug_out ) return;

  err = pthread_mutex_init(&br->br_debug_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "bridge_enable_debug: Could not initialize debug lock: %s\n", strerror(err));
    return;
  }
  br->br_mutexes_initialized |= BR_DEBUG_MUTEX_INITIALIZED;

  br->br_debug_out = fopen(pkts_out, "wt");
  if ( !br->br_debug_out )
    perror("bridge_enable_debug");
}

void bridge_allocate_ip(struct brstate *br, struct in_addr *new_ip) {
  new_ip->s_addr = htonl(__sync_fetch_and_add(&br->br_next_ip, 1));
}

void bridge_allocate(struct brstate *br, struct in_addr *new_ip, int *new_eth_ix) {
  bridge_allocate_ip(br, new_ip);
  *new_eth_ix = __sync_fetch_and_add(&br->br_eth_ix, 1);
}

int bridge_add_arp(struct brstate *br, struct arpentry *arp) {
  struct arpentry *old;
  if ( pthread_rwlock_wrlock(&br->br_arp_mutex) == 0 ) {
    int ret = 0;
    HASH_FIND(ae_hh, br->br_arp_table, &arp->ae_ip, sizeof(arp->ae_ip), old);
    if ( old ) {
      fprintf(stderr, "bridge_add_arp: already have arp\n");
      ret = -1;
    } else {
      HASH_ADD(ae_hh, br->br_arp_table, ae_ip, sizeof(arp->ae_ip), arp);
    }
    pthread_rwlock_unlock(&br->br_arp_mutex);
    return ret;
  } else return -1;
}

int bridge_del_arp(struct brstate *br, struct arpentry *arp) {
  struct arpentry *old;
  if ( pthread_rwlock_wrlock(&br->br_arp_mutex) == 0 ) {
    int ret = 0;
    HASH_FIND(ae_hh, br->br_arp_table, &arp->ae_ip, sizeof(arp->ae_ip), old);
    if ( old != arp ) {
      fprintf(stderr, "bridge_del_arp: not in table\n");
      ret = -1;
    } else {
      HASH_DELETE(ae_hh, br->br_arp_table, arp);
    }
    pthread_rwlock_unlock(&br->br_arp_mutex);
    return ret;
  } else return -1;
}

int bridge_register_sctp(struct brstate *br, struct sctpentry *se) {
  struct sctpentry *old;
  if ( pthread_rwlock_wrlock(&br->br_sctp_mutex) == 0 ) {
    int ret = 0;
    HASH_FIND(se_hh, br->br_sctp_table, &se->se_source, sizeof(se->se_source), old);
    if ( old ) {
      fprintf(stderr, "bridge_register_sctp: already have this assocation\n");
      ret = -1;
    } else {
      HASH_ADD(se_hh, br->br_sctp_table, se_source, sizeof(se->se_source), se);
    }
    pthread_rwlock_unlock(&br->br_sctp_mutex);
    return ret;
  } else return -1;
}

int bridge_unregister_sctp(struct brstate *br, struct sctpentry *se) {
  struct sctpentry *old;
  if ( pthread_rwlock_wrlock(&br->br_sctp_mutex) == 0 ) {
    int ret = 0;
    HASH_FIND(se_hh, br->br_sctp_table, &se->se_source, sizeof(se->se_source), old);
    if ( old != se ) {
      fprintf(stderr, "bridge_unregister_sctp: not in table\n");
      ret = -1;
    } else {
      HASH_DELETE(se_hh, br->br_sctp_table, se);
    }
    pthread_rwlock_unlock(&br->br_sctp_mutex);
    return ret;
  } else return -1;
}

static int setup_user_namespace(struct brstate *br, int proc_dir) {
  char buf[4096];
  int gid_map, uid_map;
  int err;

//  deny_setgroups = openat(proc_dir, "setgroups", O_WRONLY);
//  if ( deny_setgroups < 0) {
//    perror("Could not open /proc/self/setgroups");
//    return -1;
//  }
//  err = write(deny_setgroups, "deny", sizeof("deny"));
//  if ( err < 0 ) {
//    perror("write(deny_setgroups)");
//    close(deny_setgroups);
//    return -1;
//  } else
//    close(deny_setgroups);
//
  gid_map = openat(proc_dir, "gid_map", O_WRONLY);
  if ( gid_map < 0) {
    perror("Could not open /proc/self/gid_map");
    return -1;
  }

  if ( br->br_euid == 0 ) {
    SAFE_ASSERT( snprintf(buf, sizeof(buf), "0 %d 1\n100 %d 1\n",
                          br->br_daemon_gid, br->br_user_gid) < sizeof(buf) );
  } else {
    SAFE_ASSERT( snprintf(buf, sizeof(buf), "0 %d 1", br->br_gid) < sizeof(buf) );
  }

  err = write(gid_map, buf, strlen(buf));
  if ( err < 0 ) {
    perror("write(gid_map)");
    close(gid_map);
    return -1;
  } else
    close(gid_map);

  uid_map = openat(proc_dir, "uid_map", O_WRONLY);
  if ( uid_map < 0) {
    perror("Could not open /proc/self/uid_map");
    exit(1);
  }

  if ( br->br_euid == 0 ) {
    SAFE_ASSERT( snprintf(buf, sizeof(buf), "0 %d 1\n1000 %d 1\n",
                          br->br_daemon_uid, br->br_user_uid) < sizeof(buf) );
  } else {
    SAFE_ASSERT( snprintf(buf, sizeof(buf), "0 %d 1\n", br->br_uid) < sizeof(buf) );
  }
  err = write(uid_map, buf, strlen(buf));
  if ( err < 0 ) {
    perror("write(uid_map)");
    close(uid_map);
    return -1;
  } else
    close(uid_map);

  return 0;
}

static int open_proc_dir(pid_t new_proc) {
  char path_dir[PATH_MAX];

  if ( snprintf(path_dir, PATH_MAX, "/proc/%d", new_proc) >= sizeof(path_dir) ) {
    errno = ENOMEM;
    return -1;
  }

  return open(path_dir, O_CLOEXEC);
}

static int setup_namespace(struct brstate *br, pid_t new_proc,
                           int port_ix, struct in_addr *this_ip) {
  int proc_dir, err, netns;

  proc_dir = open_proc_dir(new_proc);
  if ( proc_dir < 0 ) {
    perror("setup_namespace: open_proc_dir");
    return -1;
  }

  err = setup_user_namespace(br, proc_dir);
  if ( err < 0 ) {
    close(proc_dir);
    fprintf(stderr, "setup_namespace: setup_user_namespace failed\n");
    return -1;
  }

  netns = openat(proc_dir, "ns/net", O_CLOEXEC);
  if ( netns < 0 ) {
    perror("setup_namespace: openat(ns/net)");
    close(proc_dir);
    return -1;
  }

  err = bridge_create_veth_to_ns(br, port_ix, netns, this_ip);
  if ( err < 0 ) {
    close(proc_dir);
    fprintf(stderr, "setup_namespace: bridge_create_veth_to_ns failed\n");
    return -1;
  }

  close(proc_dir);

  return 0;
}

static int bridge_create_tap(struct brstate *br, char *tap_nm, int is_tun) {
  int fd, err;
  struct ifreq ifr;

  fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
  if ( fd < 0 ) {
    perror("bridge_create_tap: open(/dev/net/tun)");
    exit(4);
  }

  memset(&ifr, 0, sizeof(ifr));
  if ( is_tun )
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  else
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

  err = ioctl(fd, TUNSETIFF, (void *) &ifr);
  if ( err < 0 ) {
    perror("bridge_create_tap: ioctl(TUNSETIFF)");
    exit(5);
  }

  strncpy(tap_nm, ifr.ifr_name, IFNAMSIZ);

  return fd;
}

static void bridge_create_bridge(struct brstate *br, const char *tap_nm) {
  char cmd_buf[512], mac_buf[32];
  int err;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s link add bridge type bridge", br->br_iproute_path);
  if ( err >= sizeof(cmd_buf) ) goto nospc;
  err = system(cmd_buf);
  if ( err != 0 ) goto cmdfailed;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s link set dev lo up", br->br_iproute_path);
  if ( err >= sizeof(cmd_buf) ) goto nospc;
  err = system(cmd_buf);
  if ( err != 0 ) goto cmdfailed;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s link set dev %s master bridge", br->br_iproute_path, tap_nm);
  if ( err >= sizeof(cmd_buf) ) goto nospc;

  err = system(cmd_buf);
  if ( err != 0 ) goto cmdfailed;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s link set dev %s up multicast off", br->br_iproute_path, tap_nm);
  if ( err >= sizeof(cmd_buf) ) goto nospc;
  err = system(cmd_buf);
  if ( err != 0 ) goto cmdfailed;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s link set dev bridge up multicast off", br->br_iproute_path);
  if ( err >= sizeof(cmd_buf) ) goto nospc;
  err = system(cmd_buf);
  if ( err != 0 ) goto cmdfailed;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s addr add %s/8 dev bridge",
                 br->br_iproute_path,
                 inet_ntop(AF_INET, &br->br_bridge_addr,
                           mac_buf, sizeof(mac_buf)));
  if ( err >= sizeof(cmd_buf) ) goto nospc;
  err = system(cmd_buf);
  if ( err != 0 ) goto cmdfailed;

  // Set up ebtables to drop all packets, except those destined for
  // the bridge itself or the admin app

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s -P FORWARD ACCEPT", br->br_ebroute_path);
  if ( err >= sizeof(cmd_buf) ) goto nospc;
  err = system(cmd_buf);
  if ( err != 0 ) goto cmdfailed;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s -A FORWARD --source %s -j ACCEPT",
                 br->br_ebroute_path, mac_ntop(br->br_tap_mac, mac_buf, sizeof(mac_buf)));
  if ( err >= sizeof(cmd_buf) ) goto nospc;
  err = system(cmd_buf);
  if ( err != 0 ) goto cmdfailed;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s -N INTRUSTD -P RETURN", br->br_ebroute_path);
  if ( err >= sizeof(cmd_buf) ) goto nospc;
  err = system(cmd_buf);
  if ( err != 0 ) goto cmdfailed;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s -A INTRUSTD --destination %s -j ACCEPT",
                 br->br_ebroute_path, mac_ntop(br->br_tap_mac, mac_buf, sizeof(mac_buf)));
  if ( err >= sizeof(cmd_buf) ) goto nospc;
  err = system(cmd_buf);
  if ( err != 0 ) goto cmdfailed;

  // TODO may want to prevent ARPing between containers
  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s -A INTRUSTD -p ARP -j ACCEPT",
                 br->br_ebroute_path);
  if ( err >= sizeof(cmd_buf) ) goto nospc;
  err = system(cmd_buf);
  if ( err != 0 ) goto cmdfailed;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s -A FORWARD -j INTRUSTD", br->br_ebroute_path);
  if ( err >= sizeof(cmd_buf) ) goto nospc;
  err = system(cmd_buf);
  if ( err != 0 ) goto cmdfailed;

//  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s -Ln", br->br_ebroute_path);
//  if ( err >= sizeof(cmd_buf) ) goto nospc;
//  err = system(cmd_buf);
//  if ( err != 0 ) goto cmdfailed;

  return;

 cmdfailed:
  fprintf(stderr, "bridge_create_bridge: '%s' failed with %d\n", cmd_buf, err);
  exit(err);

 nospc:
  fprintf(stderr, "bridge_create_bridge: Not enough space in cmd_buf\n");
  exit(3);
}

static void bridge_respond_error(struct brstate *br, int sts) {
 struct brctlrsp r = { .bcr_sts = sts };
 int err;

 err = send(br->br_comm_fd[0], &r, sizeof(r), 0);
 if ( err < 0 )
   perror("bridge_respond_error");
}

static void bridge_respond_success(struct brstate *br) {
  bridge_respond_error(br, 0);
}

static void bridge_do_setup_ns(struct brstate *br, struct brctlmsg *_msg, pid_t owner) {
  struct brctlmsg_setupns *msg = (struct brctlmsg_setupns *) _msg;
  int err;

  err = setup_namespace(br, owner, msg->bcm_port_ix,
                        &msg->bcm_ip);
  if ( err < 0 ) {
    fprintf(stderr, "bridge_do_setup_ns: setup_namespace failed\n");
    bridge_respond_error(br, -1);
    return;
  }

  fprintf(stderr, "Bridge: set up namespace\n");

  bridge_respond_success(br);
}

static void bridge_do_new_tunnel(struct brstate *br, struct brctlmsg *_msg) {
  struct brctlmsg_newtun *msg = (struct brctlmsg_newtun *) _msg;
  int err;
  char cmd_buf[512];

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s -I TABLE%d -1 --out-if in%d -j ACCEPT",
                 br->br_ebroute_path, msg->bcm_ports[0], msg->bcm_ports[1]);
  if ( err >= sizeof(cmd_buf) ) goto overflow;
  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_error;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s -I TABLE%d -1 --out-if in%d -j ACCEPT",
                 br->br_ebroute_path, msg->bcm_ports[0], msg->bcm_ports[1]);
  if ( err >= sizeof(cmd_buf) ) goto overflow;
  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_error;

  bridge_respond_success(br);
  return;

 overflow:
  fprintf(stderr, "bridge_do_new_tunnel: no space for command\n");
  bridge_respond_error(br, -2);
  return;

 cmd_error:
  fprintf(stderr, "bridge_do_new_tunnel: '%s' failed: %d\n", cmd_buf, err);
  bridge_respond_error(br, -2);
  return;
}

static void bridge_do_del_tunnel(struct brstate *br, struct brctlmsg *_msg) {
  struct brctlmsg_deltun *msg = (struct brctlmsg_deltun *) _msg;
  int err;
  char cmd_buf[512];

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s -D TABLE%d --out-if in%d -j ACCEPT",
                 br->br_ebroute_path, msg->bcm_ports[0], msg->bcm_ports[1]);
  if ( err >= sizeof(cmd_buf) ) goto overflow;
  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_error;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s -D TABLE%d --out-if in%d -j ACCEPT",
                 br->br_ebroute_path, msg->bcm_ports[1], msg->bcm_ports[0]);
  if ( err >= sizeof(cmd_buf) ) goto overflow;
  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_error;

  bridge_respond_success(br);
  return;

 overflow:
  fprintf(stderr, "bridge_do_del_tunnel: no space for command\n");
  bridge_respond_error(br, -1);
  return;

 cmd_error:
  fprintf(stderr, "bridge_do_del_tunnel: '%s' failed: %d\n", cmd_buf, err);
  bridge_respond_error(br, -1);
  return;
}

static void bridge_do_disconnect_port(struct brstate *br, struct brctlmsg *_msg) {
  struct brctlmsg_delport *msg = (struct brctlmsg_delport *) _msg;
  char in_if_name[IFNAMSIZ];
  int err;

  fprintf(stderr, "bridge_do_disconnect_port: port %d\n", msg->bcm_port);

  err = snprintf(in_if_name, sizeof(in_if_name), "in%d", msg->bcm_port);
  if ( err >= sizeof(in_if_name) ) {
    fprintf(stderr, "bridge_do_disconnect_port: in_if_name overflow\n");
    bridge_respond_error(br, -1);
    return;
  }

  err = bridge_disconnect_iface(br, in_if_name);
  if ( err < 0 ) {
    fprintf(stderr, "bridge_do_disconnect_port: could not remove %s\n", in_if_name);
    bridge_respond_error(br, -1);
    return;
  }

  err = bridge_delete_veth(br, in_if_name);
  if ( err < 0 ) {
    fprintf(stderr, "bridge_do_disconnect_port: could not delete interface %s\n", in_if_name);
    bridge_respond_error(br, -1);
    return;
  }

  err = bridge_remove_ebtable_spoof(br, msg->bcm_port, &msg->bcm_arp);
  if ( err < 0 ) {
    fprintf(stderr, "bridge_do_disconnect_port: unable to delete anti-spoof ebtable rule\n");
    bridge_respond_error(br, -1);
    return;
  }

  err = bridge_remove_ebtable_sub(br, msg->bcm_port);
  if ( err < 0 ) {
    fprintf(stderr, "bridge_do_disconnect_port: unable to remove ebtable\n");
    bridge_respond_error(br, -1);
    return;
  }

  bridge_respond_success(br);
}

static void bridge_do_mark_as_admin(struct brstate *br, struct brctlmsg *_msg) {
  int err;
  char cmd_buf[512], mac_dbg[64];
  struct brctlmsg_markadmin *msg = (struct brctlmsg_markadmin *)_msg;

  // Ask ebtables to accept all on this table
  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s -F TABLE%d",
                 br->br_ebroute_path, msg->bcm_port);
  if ( err >= sizeof(cmd_buf) ) goto overflow;

  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_error;

  // Add the anti-spoofing rule
  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s -A TABLE%d -p IPv4 --ip-source ! %s -j DROP",
                 br->br_ebroute_path, msg->bcm_port,
                 inet_ntop(AF_INET, &msg->bcm_arp.ae_ip.s_addr,
                           mac_dbg, sizeof(mac_dbg)));
  if ( err >= sizeof(cmd_buf) ) goto overflow;

  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_error;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s -P TABLE%d ACCEPT", br->br_ebroute_path, msg->bcm_port);
  if ( err >= sizeof(cmd_buf) ) goto overflow;

  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_error;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s -I INTRUSTD -1 --destination %s -j ACCEPT",
                 br->br_ebroute_path,
                 mac_ntop(msg->bcm_arp.ae_mac, mac_dbg, sizeof(mac_dbg)));
  if ( err >= sizeof(cmd_buf) ) goto overflow;

  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_error;

  bridge_respond_success(br);
  return;

 overflow:
  fprintf(stderr, "bridge_mark_as_admin: command overflow\n");
  bridge_respond_error(br, -1);
  return;

 cmd_error:
  fprintf(stderr, "bridge_mark_as_admin: command '%s' fails with %d\n", cmd_buf, err);
  bridge_respond_error(br, -1);
  return;
}

static int open_netns(pid_t p) {
  char netns_path[PATH_MAX];
  int err;

  err = snprintf(netns_path, sizeof(netns_path),
                 "/proc/%d/ns/net", p);
  if ( err >= sizeof(netns_path) ) {
    fprintf(stderr, "open_netns: path overflow\n");
    errno = ENOMEM;
    return -1;
  }

  return open(netns_path, O_CLOEXEC);
}

static int bridge_set_arp_ignore() {
  FILE *arp_ignore = fopen("/proc/sys/net/ipv4/conf/bridge/arp_ignore", "wt");
  if ( !arp_ignore )
    return -1;

  fprintf(arp_ignore, "1");
  fclose(arp_ignore);

  return 0;
}

static int bridge_setup_main(void *br_ptr) {
  struct brstate *br = (struct brstate *)br_ptr;
  char tap_nm[IFNAMSIZ], cmd_buf[512];
  int tap, err, yes = 1, parent_netns;

  close(br->br_comm_fd[1]);

  if ( br->br_euid != 0 ) {
    fprintf(stderr, "WARNING: running in unprivileged mode.\n");
    fprintf(stderr, " Containers will be unable to access the internet\n");
    fprintf(stderr, " Applications will not have privilege isolation within containers\n");
  }

  tap = bridge_create_tap(br, tap_nm, 0);
  fprintf(stderr, "Created tap device %s\n", tap_nm);

  fprintf(stderr, "Creating bridge\n");
  bridge_create_bridge(br, tap_nm);
  fprintf(stderr, "Created bridge\n");

  fprintf(stderr, "Creating internet link\n");

  err = bridge_create_veth(br, "internet", INET_LINK_NAME, 1);
  if ( err < 0 ) {
    fprintf(stderr, "bridge_setup_main: bridge_create_veth failed");
    return 1;
  }

  parent_netns = open_netns(g_main_pid);
  if ( parent_netns < 0 ) {
    perror("bridge_setup_main: open_netns");
    return 1;
  }

  fprintf(stderr, "got parent net ns %d\n", parent_netns);

  err = bridge_move_if_to_ns(br, INET_LINK_NAME, parent_netns);
  if ( err < 0 ) {
    fprintf(stderr, "bridge_setup_main: bridge_move_if_to_ns failed\n");
    close(parent_netns);
    return 1;
  }
  close(parent_netns);

  fprintf(stderr, "Moved " INET_LINK_NAME " to parent\n");

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s addr add " INTERNET_GATEWAY " dev internet", br->br_iproute_path);
  if ( err >= sizeof(cmd_buf) ) {
    fprintf(stderr, "bridge_setup_main: command overflow while adding internet gateway address\n");
    return 1;
  }

  err = system(cmd_buf);
  if ( err != 0 ) {
    fprintf(stderr, "bridge_setup_main: '%s' returned %d\n", cmd_buf, err);
    return 1;
  }

  fprintf(stderr, "Sending fds\n");
  err = send_fd(br->br_comm_fd[0], 1, &tap);
  if ( err < 0 ) {
    perror("bridge_setup_main: send_fd");
    return 1;
  }

  fprintf(stderr, "Sent fds\n");
  // Enable receiving credentials on this socket
  if ( setsockopt(br->br_comm_fd[0], SOL_SOCKET, SO_PASSCRED,
                  &yes, sizeof(yes)) < 0 ) {
    perror("setsockopt(SO_PASSCRED)");
    return 1;
  }

  // Set arp ignore to 1
  if ( bridge_set_arp_ignore() < 0 ) {
    fprintf(stderr, "bridge_setup_main: bridge_set_arp_ignore failed\n");
    return 1;
  }

  fprintf(stderr, "Waiting for bridge message\n");
  // Read from the communications fd and serve requests
  while (1) {
    union {
      struct brctlmsg msg;
      char buf[8192];
    } rcvbuf;
    int msgsz;
    char control_buf[CMSG_SPACE(sizeof(struct ucred))];
    struct iovec iov
      = { .iov_base = rcvbuf.buf,
          .iov_len = sizeof(rcvbuf.buf) };
    struct msghdr msginfo
      = { .msg_name = NULL,
          .msg_namelen = 0,
          .msg_iov = &iov,
          .msg_iovlen = 1,
          .msg_control = control_buf,
          .msg_controllen = sizeof(control_buf),
          .msg_flags = 0 };

    msgsz = recvmsg(br->br_comm_fd[0], &msginfo, 0);
    if ( msgsz == 0 ) {
      fprintf(stderr, "bridge shutting down\n");
      // TODO cleanup actions
      return 0;
    } else if ( msgsz < 0 ) {
      perror("bridge: recvmsg");
      if ( errno == EAGAIN || errno == EINTR ) continue;
      return 1;
    }

    if ( msgsz < sizeof(rcvbuf.msg) ) {
      fprintf(stderr, "bridge: not enough space in buffer\n");
      bridge_respond_error(br, -1);
      continue;
    }

    switch ( rcvbuf.msg.bcm_what ) {
    case BR_SETUP_NAMESPACE:
      if ( msginfo.msg_controllen == 0 ) {
        fprintf(stderr, "bridge: no control message with BR_SETUP_NAMESPACE\n");
        bridge_respond_error(br, -1);
      } else {
        struct cmsghdr *cmsg;
        struct ucred uc;

        cmsg = CMSG_FIRSTHDR(&msginfo);
        if ( cmsg->cmsg_level != SOL_SOCKET ||
             cmsg->cmsg_type != SCM_CREDENTIALS ||
             cmsg->cmsg_len != CMSG_LEN(sizeof(struct ucred)) ) {
          fprintf(stderr, "bridge: no credentials sent with BR_SETUP_NAMESPACE\n");
          bridge_respond_error(br, -1);
          continue;
        }

        memcpy(&uc, CMSG_DATA(cmsg), sizeof(uc));

        fprintf(stderr, "bridge: request to setup %d\n", uc.pid);
        bridge_do_setup_ns(br, &rcvbuf.msg, uc.pid);
      }
      break;

    case BR_NEW_TUNNEL:
      bridge_do_new_tunnel(br, &rcvbuf.msg);
      break;

    case BR_DEL_TUNNEL:
      bridge_do_del_tunnel(br, &rcvbuf.msg);
      break;

    case BR_DISCONNECT_PORT:
      bridge_do_disconnect_port(br, &rcvbuf.msg);
      break;

    case BR_MARK_AS_ADMIN:
      bridge_do_mark_as_admin(br, &rcvbuf.msg);
      break;

    default:
      fprintf(stderr, "Nonsense message received in bridge %d\n", rcvbuf.msg.bcm_what);
      bridge_respond_error(br, -2);
      break;
    }
  }

  return 0;
}

static int bridge_setup_ns(struct brstate *br) {
  void *stack;
  int err, new_proc;
  char cmd_buf[512];

  err = posix_memalign(&stack, sysconf(_SC_PAGE_SIZE), BRIDGE_STACK_SIZE);
  if ( err != 0 ) {
    fprintf(stderr, "bridge_setup_ns: could not allocate stack\n");
    return -1;
  }
  fprintf(stderr, "bridge_setup_ns: stack is %p\n", stack);

  err = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, br->br_comm_fd);
  if ( err < 0 ) {
    perror("bridge_setup_ns: socketpair");
    return -1;
  }

  if ( br->br_euid == 0 ) {
    if ( seteuid(0) < 0 ) {
      perror("seteuid(0)");
      exit(1);
    }

    if ( setegid(0) < 0 ) {
      perror("setegid(0)");
      exit(1);
    }
  }

  g_main_pid = getpid();

  new_proc =
    clone(&bridge_setup_main, stack + BRIDGE_STACK_SIZE,
          CLONE_NEWNET | SIGCHLD, br);
  if ( new_proc == -1 ) {
    perror("bridge_setup_ns: clone");
    return -1;
  }

  close(br->br_comm_fd[0]);
  br->br_comm_fd[0] = 0;

  err = recv_fd(br->br_comm_fd[1], 1, &br->br_tapfd);
  if ( err < 0 ) {
    fprintf(stderr, "bridge_setup_ns: could not fetch TAP fd\n");
    return -1;
  }

  fprintf(stderr, "Got tap fd(%d)\n", br->br_tapfd);

  fcntl(br->br_tapfd, F_SETFD, FD_CLOEXEC);

  if ( set_socket_nonblocking(br->br_tapfd) < 0 )
    fprintf(stderr, "Could not set TAP non blocking\n");

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s addr add " INTERNET_GATEWAY "/8 dev " INET_LINK_NAME,
                 br->br_iproute_path);
  if ( err >= sizeof(cmd_buf) ) goto overflow;

  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_error;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s link set dev " INET_LINK_NAME " up",
                 br->br_iproute_path);
  if ( err >= sizeof(cmd_buf) ) goto overflow;

  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_error;

  return 0;

 overflow:
  fprintf(stderr, "bridge_setup_ns: command overflow while setting up " INET_LINK_NAME "\n");
  return -1;

 cmd_error:
  fprintf(stderr, "bridge_setup_ns: '%s' returned %d\n", cmd_buf, err);
  return -1;
}

// Utilities

void random_mac(unsigned char *mac) {
  // Taken from linux eth_random_addr;
  int err = RAND_bytes((unsigned char *)mac, ETH_ALEN);
  if ( !err ) {
    fprintf(stderr, "random_mac fails\n");
    ERR_print_errors_fp(stderr);
  }

  mac[0] &= 0xFE; // Clear multicast bit
  mac[1] |= 0x02; // Local assignment bit
}

char *mac_ntop(const unsigned char *mac, char *str, int str_sz) {
  snprintf(str, str_sz, "%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return str;
}

// Container utils

int bridge_setup_root_uid_gid(struct brstate *br) {
  int err = syscall(SYS_setuid, 0); //setreuid(0, 0);
  if ( err < 0 ) {
    errno = -err;
    perror("brudge_setup_root_uid_gid: setreuid");
    return -1;
  }

  err = syscall(SYS_setgid, 0); //setregid(0, 0);
  if ( err < 0 ) {
    errno = -err;
    perror("bridge_setup_root_uid_gid: setregid");
    return -1;
  }

  return 0;
}

int bridge_set_up_networking(struct brstate *br) {
  char cmd_buf[512];
  int err;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s link set dev lo up", br->br_iproute_path);
  if ( err >= sizeof(cmd_buf) ) {
    fprintf(stderr, "bridge_set_up_networking: no space in command buffer\n");
    return -1;
  }

  err = system(cmd_buf);
  if ( err != 0 ) {
    fprintf(stderr, "bridge_set_up_networking: '%s' command fails: %d\n", cmd_buf, err);
    return -1;
  }

  return 0;
}

static int bridge_remove_ebtable_spoof(struct brstate *br, int port, struct arpentry *arp) {
  char cmd_buf[512], ip_addr_str[INET6_ADDRSTRLEN];
  int err;

  err = snprintf(cmd_buf, sizeof(cmd_buf),
                 "%s -D TABLE%d -p IPv4 --ip-source ! %s -j DROP",
                 br->br_ebroute_path, port,
                 inet_ntop(AF_INET, &arp->ae_ip.s_addr, ip_addr_str, sizeof(ip_addr_str)));
  if ( err >= sizeof(cmd_buf) ) {
    fprintf(stderr, "bridge_remove_ebtable_spoof: command overflow\n");
    return -1;
  }

  err = system(cmd_buf);
  if ( err != 0 ) {
    fprintf(stderr, "bridge_remove_ebtable_spoof: '%s' returned %d\n",
            cmd_buf, err);
    return -1;
  }

  return 0;
}

static int bridge_remove_ebtable_sub(struct brstate *br, int port) {
  char cmd_buf[512];
  int err;

  err = snprintf(cmd_buf, sizeof(cmd_buf),
                 "%s -D FORWARD --in-if in%d -j TABLE%d",
                 br->br_ebroute_path, port, port);
  if ( err >= sizeof(cmd_buf) ) goto cmd_overflow;

  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_failed;

  err = snprintf(cmd_buf, sizeof(cmd_buf),
                 "%s -X TABLE%d", br->br_ebroute_path, port);
  if ( err >= sizeof(cmd_buf) ) goto cmd_overflow;

  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_failed;

  err = snprintf(cmd_buf, sizeof(cmd_buf),
                 "%s -Ln", br->br_ebroute_path);
  err = system(cmd_buf);

  return 0;

 cmd_overflow:
    fprintf(stderr, "bridge_remove_ebtable_sub: command overflow\n");
    return -1;

 cmd_failed:
    fprintf(stderr, "bridge_remove_ebtable_sub: '%s' returned %d\n",
            cmd_buf, err);
    return -1;
}

int bridge_disconnect_port(struct brstate *br, int port, struct arpentry *arp) {
  struct brctlmsg_delport msg
    = { .bcm_msg = { .bcm_what = BR_DISCONNECT_PORT },
        .bcm_port = port };
  int err;

  memcpy(&msg.bcm_arp, arp, sizeof(msg.bcm_arp));

  if ( pthread_mutex_lock(&br->br_comm_mutex) == 0 ) {
    err = send(br->br_comm_fd[1], &msg, sizeof(msg), 0);
    if ( err < 0 ) {
      perror("bridge_disconnect_port: send");
    } else {
      struct brctlrsp rsp;

      err = bridge_del_arp(br, arp);
      if ( err < 0 ) {
        fprintf(stderr, "bridge_disconnect_port: could not delete arp\n");
        // Do not return, because we need to wait for the response
      }

      err = recv(br->br_comm_fd[1], &rsp, sizeof(rsp), 0);
      if ( err < 0 ) {
        perror("bridge_disconnect_port: recv");
      }

      err = rsp.bcr_sts;
    }
    pthread_mutex_unlock(&br->br_comm_mutex);
    return err;
  } else
    return -1;
}

//  pid_t new_proc;
//  int err;
//  char in_if_name[IFNAMSIZ];
//
//  fprintf(stderr, "bridge_disconnect_port: port %d\n", port);
//
//  err = snprintf(in_if_name, sizeof(in_if_name), "in%d", port);
//  if ( err >= sizeof(in_if_name) ) {
//    fprintf(stderr, "bridge_disconnect_port: in_if_name overflow\n");
//    return -1;
//  }
//
//  new_proc = fork();
//  if ( new_proc < 0 ) {
//    perror("bridge_disconnect_port: fork");
//    return -1;
//  }
//
//  if ( new_proc == 0 ) {
//    err = bridge_enter_user_namespace(br);
//    if ( err < 0 ) {
//      fprintf(stderr, "bridge_disconnect_port: could not enter user namespace\n");
//      exit(1);
//    }
//
//    err = bridge_enter_network_namespace(br);
//    if ( err < 0 ) {
//      fprintf(stderr, "bridge_disconnect_port: could not enter bridge network namespace\n");
//      exit(1);
//    }
//
//    err = bridge_disconnect_iface(br, in_if_name);
//    if ( err < 0 ) {
//      fprintf(stderr, "bridge_disconnect_port: could not remove %s\n", in_if_name);
//      exit(1);
//    }
//
//    err = bridge_delete_veth(br, in_if_name);
//    if ( err < 0 ) {
//      fprintf(stderr, "bridge_disconnect_port: could not delete interface %s\n", in_if_name);
//      exit(1);
//    }
//
//    // TODO delete ebtable
//
//    err = bridge_remove_ebtable_spoof(br, port, arp);
//    if ( err < 0 ) {
//      fprintf(stderr, "bridge_disconnect_port: unable to delete anti-spoof ebtable rule\n");
//      exit(1);
//    }
//
//    err = bridge_remove_ebtable_sub(br, port);
//    if ( err < 0 ) {
//      fprintf(stderr, "bridge_disconnect_port: unable to remove ebtable\n");
//      exit(1);
//    }
//
//    exit(EXIT_SUCCESS);
//  } else {
//    int sts = 0;
//
//    err = bridge_del_arp(br, arp);
//    if ( err < 0 ) {
//      fprintf(stderr, "bridge_disconnect_port: could not delete arp\n");
//      // DO not return, because we need to wait for new_proc
//    }
//
//    err = waitpid(new_proc, &sts, 0);
//    if ( err < 0 ) {
//      perror("bridge_disconnect_port: waitpid");
//      return -1;
//    }
//
//    fprintf(stderr, "bridge_disconnect_port: got status %d\n", sts);
//
//    if ( sts != 0 ) {
//      fprintf(stderr, "bridge_disconnect_port: namespace child exited with %d\n", sts);
//      return -1;
//    }
//
//    return 0;
//  }
//}

static int bridge_setup_container_ebtable(struct brstate *br, int port_ix,
                                          const char *in_if_name,
                                          const char *ip_addr_str) {
  char cmd_buf[512];
  int err;

  // Every port gets an automatic ebtable
  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s -N TABLE%d -P RETURN",
                 br->br_ebroute_path, port_ix);
  if ( err >= sizeof(cmd_buf) ) goto overflow;
  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_error;

  // Anything coming in from this port, should be sent to this table
  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s -I FORWARD -1 --in-if %s -j TABLE%d",
                 br->br_ebroute_path, in_if_name, port_ix);
  if ( err >= sizeof(cmd_buf) ) goto overflow;
  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_error;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s -A TABLE%d -p IPv4 --ip-source ! %s -j DROP",
                 br->br_ebroute_path, port_ix, ip_addr_str);
  if ( err >= sizeof(cmd_buf) ) goto overflow;
  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_error;

//  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s -Ln", br->br_ebroute_path);
//  if ( err >= sizeof(cmd_buf) ) goto overflow;
//  err = system(cmd_buf);
//  if ( err != 0 ) goto cmd_error;

  return 0;

  overflow:
    fprintf(stderr, "bridge_setup_container_ebtable: no space for commmand '%s'\n", cmd_buf);
    return -1;

  cmd_error:
    fprintf(stderr, "bridge_setup_container_ebtable: '%s' failed: %d\n", cmd_buf, err);
    return -1;
}

int bridge_create_veth_to_ns(struct brstate *br, int port_ix, int this_netns, struct in_addr *this_ip) {
  int err;

  char in_if_name[IFNAMSIZ], out_if_name[IFNAMSIZ], ip_addr_str[INET6_ADDRSTRLEN];

  inet_ntop(AF_INET, this_ip, ip_addr_str, sizeof(ip_addr_str));
  fprintf(stderr, "bridge_create_veth_to_ns: create veth to %d: IP %s\n", this_netns, ip_addr_str);

  err = snprintf(in_if_name, sizeof(in_if_name), "in%d", port_ix);
  if ( err >= sizeof(in_if_name) ) {
    fprintf(stderr, "bridge_create_veth_to_ns: in_if_name overflow\n");
    return -1;
  }

  err = snprintf(out_if_name, sizeof(out_if_name), "out%d", port_ix);
  if ( err >= sizeof(out_if_name) ) {
    fprintf(stderr, "bridge_create_veth_to_ns: out_if_name overflow\n");
    return -1;
  }

  err = bridge_create_veth(br, in_if_name, out_if_name, 1);
  if ( err < 0 ) {
    fprintf(stderr, "bridge_create_veth_to_ns: could not create veth\n");
    return -1;
  }

  err = bridge_move_if_to_ns(br, out_if_name, this_netns);
  if ( err < 0 ) {
    fprintf(stderr, "bridge_create_veth_to_ns: could not move interface\n");
    return -1;
  }

  err = bridge_setup_container_ebtable(br, port_ix, in_if_name, ip_addr_str);
  if ( err < 0 ) {
    fprintf(stderr, "bridge_create_veth_to_ns: could not set up ebtables\n");
    return -1;
  }

  return 0;
}

static int bridge_move_if_to_ns(struct brstate *br, const char *if_name, int netns) {
  int nl_sk, err;
  struct ifreq ifr;

  struct {
    struct nlmsghdr nl;
    struct ifinfomsg ifi;
    struct rtattr ns_fd_a;
    int ns_fd;
  } INTRUSTD_PACKED nl_msg;
  struct nlmsghdr rsp;
  struct nlmsgerr nl_err;
  char recv_buf[512];

  nl_sk = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if ( nl_sk < 0 ) {
    perror("bridge_move_if_to_ns: socket");
    return -1;
  }

  strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));

  if ( ioctl(nl_sk, SIOCGIFINDEX, &ifr, sizeof(ifr)) < 0 ) {
    perror("bridge_move_if_to_ns: ioctl(SIOCGIFINDEX)");
    close(nl_sk);
    return -1;
  }

  // fprintf(stderr, "bridge_move_if_to_ns: index of iface %s is %d\n", if_name, ifr.ifr_ifindex);

  // Set up netlink message

  nl_msg.nl.nlmsg_len = sizeof(nl_msg);
  nl_msg.nl.nlmsg_type = RTM_SETLINK;
  nl_msg.nl.nlmsg_flags = NLM_F_ACK | NLM_F_REQUEST;
  nl_msg.nl.nlmsg_seq = 0;
  nl_msg.nl.nlmsg_pid = getpid();
  nl_msg.ifi.ifi_family = AF_UNSPEC;
  nl_msg.ifi.ifi_type = ARPHRD_ETHER;
  nl_msg.ifi.ifi_index = ifr.ifr_ifindex;
  nl_msg.ifi.ifi_flags = 0;
  nl_msg.ifi.ifi_change = 0xFFFFFFFF;
  nl_msg.ns_fd_a.rta_type = IFLA_NET_NS_FD;
  nl_msg.ns_fd_a.rta_len = RTA_LENGTH(sizeof(int));
  nl_msg.ns_fd = netns;

  err = setregid(0, 0);
  if ( err < 0 ) {
    perror("bridge_move_if_to_ns: setregid");
    close(nl_sk);
    return -1;
  }

  err = send(nl_sk, (void *) &nl_msg, sizeof(nl_msg), 0);
  if ( err < 0 ) {
    perror("bridge_move_if_to_ns: send(nl_sk)");
    close(nl_sk);
    return -1;
  }

  err = recv(nl_sk, (void *)recv_buf, sizeof(recv_buf), 0);
  if ( err < 0 ) {
    perror("bridge_move_if_to_ns: recv(nl_sk)");
    close(nl_sk);
    return -1;
  }
  close(nl_sk);

  if ( err < sizeof(rsp) ) {
    fprintf(stderr, "bridge_move_if_to_ns: not enough bytes in response: %d < %zu\n",
            err, sizeof(rsp));
    return -1;
  }

  memcpy(&rsp, recv_buf, sizeof(rsp));
  if ( err < rsp.nlmsg_len ) {
    fprintf(stderr, "bridge_move_if_to_ns: did not receive enough bytes in response\n");
    return -1;
  }

  if ( rsp.nlmsg_type != NLMSG_ERROR ) {
    fprintf(stderr, "bridge_move_if_to_ns: did not get ack from kernel\n");
    return -1;
  }

  if ( rsp.nlmsg_len < (sizeof(rsp) + sizeof(nl_err)) ) {
    fprintf(stderr, "bridge_move_if_to_ns: invalid netlink response\n");
    return -1;
  }

  memcpy(&nl_err, recv_buf + sizeof(rsp), sizeof(nl_err));
  if ( nl_err.error != 0 ) {
    fprintf(stderr, "bridge_move_if_to_ns: could not set namespace: %s\n", strerror(nl_err.error));
    return -1;
  }

  fprintf(stderr, "bridge_move_if_to_ns: moved %s to %d\n", if_name, netns);
  //  err = system("ifconfig -a");

  return 0;
}

static int bridge_create_veth(struct brstate *br,
                              const char *in_if_name, const char *out_if_name,
                              int set_in_master ) {
  char cmd_buf[512];
  int err;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s link add %s type veth peer name %s",
                 br->br_iproute_path, in_if_name, out_if_name);
  if ( err >= sizeof(cmd_buf) ) goto overflow;

  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_fails;

  if ( set_in_master ) {
    err = snprintf(cmd_buf, sizeof(cmd_buf), "%s link set %s master bridge",
                   br->br_iproute_path, in_if_name);
    if ( err >= sizeof(cmd_buf) ) goto overflow;

    err = system(cmd_buf);
    if ( err != 0 ) goto cmd_fails;
  }

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s link set %s up",
                 br->br_iproute_path, in_if_name);
  if ( err >= sizeof(cmd_buf) ) goto overflow;

  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_fails;

  return 0;

 overflow:
  fprintf(stderr, "bridge_create_veth: '%s' overflowed command buffer\n", cmd_buf);
  return -1;

 cmd_fails:
  fprintf(stderr, "bridge_create_veth: '%s' fails with %d\n", cmd_buf, err);
  return -1;
}

static int bridge_disconnect_iface(struct brstate *br, const char *if_name) {
  char cmd_buf[512];
  int err;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s link set %s nomaster",
                 br->br_iproute_path, if_name);
  if ( err >= sizeof(cmd_buf) ) goto overflow;

  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_fails;

  return 0;

 overflow:
  fprintf(stderr, "bridge_disconnect_iface: '%s' overflowed command buffer\n", cmd_buf);
  return -1;

 cmd_fails:
  fprintf(stderr, "bridge_disconnect_iface: '%s' fails with %d\n", cmd_buf, err);
  return -1;
}

static int bridge_delete_veth(struct brstate *br, const char *if_name) {
  char cmd_buf[512];
  int err;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s link delete dev %s type veth",
                 br->br_iproute_path, if_name);
  if ( err >= sizeof(cmd_buf) ) goto overflow;

  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_fails;

  return 0;

 overflow:
  fprintf(stderr, "bridge_delete_veth: '%s' overflowed command buffer\n", cmd_buf);
  return -1;

 cmd_fails:
  fprintf(stderr, "bridge_delete_veth: '%s' fails with %d\n", cmd_buf, err);
  return -1;
}

static int find_hw_addr(const char *if_name, unsigned char *mac_addr) {
  int sk;
  struct ifreq ifr;

  sk = socket(AF_UNIX, SOCK_DGRAM, 0);
  if ( sk < 0 ) {
    perror("find_hw_addr: socket");
    return -1;
  }

  if ( strlen(if_name) >= sizeof(ifr.ifr_name) ) {
    close(sk);
    fprintf(stderr, "find_hw_addr: interface name too long\n");
    return -1;
  }

  strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));

  if ( ioctl(sk, SIOCGIFHWADDR, &ifr, sizeof(ifr)) < 0 ) {
    close(sk);
    return -1;
  }

  close(sk);

  if ( ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER ) {
    fprintf(stderr, "find_hw_addr: invalid hardware address returned\n");
    return -1;
  }

  memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

  return 0;
}

static int enable_internet_in_container(struct brstate *br) {
  char cmd_buf[512];
  int err;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s route add default via " INTERNET_GATEWAY,
                 br->br_iproute_path);
  if ( err >= sizeof(cmd_buf) ) {
    fprintf(stderr, "enable_internet_in_container: command buffer overflow\n");
    return -1;
  }

  err = system(cmd_buf);
  if ( err != 0 ) {
    fprintf(stderr, "enable_internet_in_container: command '%s' failed: %d\n",
            cmd_buf, err);
    return -1;
  }

  return 0;
}

// Ask the bridge to accept all traffic going in and out of this port
int bridge_mark_as_admin(struct brstate *br, int port_ix, struct arpentry *arp) {
  struct brctlmsg_markadmin msg
    = { .bcm_msg = { .bcm_what = BR_MARK_AS_ADMIN },
        .bcm_port = port_ix };

  memcpy(&msg.bcm_arp, arp, sizeof(msg.bcm_arp));

  if ( pthread_mutex_lock(&br->br_comm_mutex) == 0 ) {
    int ret = 0, err;
    err = send(br->br_comm_fd[1], &msg, sizeof(msg), 0);
    if ( err < 0 ) {
      perror("bridge_mark_as_admin: send");
      ret = -1;
    } else {
      struct brctlrsp rsp = { .bcr_sts = -1 };
      err = recv(br->br_comm_fd[1], &rsp, sizeof(rsp), 0);
      if ( err < 0 ) {
        perror("bridge_mark_as_admi: recv");
        ret = -1;
      } else
        ret = rsp.bcr_sts;

      if ( ret == 0 ) {
        ret = enable_internet_in_container(br);
        if ( ret < 0 ) {
          fprintf(stderr, "bridge_mark_as_admin: enable_internet_in_container fails\n");
        }
      }
    }
    pthread_mutex_unlock(&br->br_comm_mutex);
    return ret;
  } else
    return -1;
}

static void brtunnel_deinit(struct brtunnel *tun) {
  struct brctlmsg_deltun msg;
  struct brstate *br = tun->brtun_br;
  int err;

  msg.bcm_msg.bcm_what = BR_DEL_TUNNEL;
  memcpy(msg.bcm_ports, tun->brtun_ports, sizeof(msg.bcm_ports));

  if ( pthread_mutex_lock(&br->br_comm_mutex) == 0 ) {
    err = send(br->br_comm_fd[1], &msg, sizeof(msg), 0);
    if ( err < 0 ) {
      perror("brtunnel_deinit: send");
    } else {
      struct brctlrsp rsp;
      err = recv(br->br_comm_fd[1], &rsp, sizeof(rsp), 0);
      if ( err < 0 ) {
        perror("brtunnel_deinit: recv");
      } else if ( rsp.bcr_sts < 0 ) {
        fprintf(stderr, "brtunnel_deinit: bridge signalled error while deinitializing\n");
      }
    }
    pthread_mutex_unlock(&br->br_comm_mutex);
  }
}

static void brtunnel_evtfn(struct eventloop *el, int op, void *arg) {
  struct qdevent *qde = arg;
  struct brtunnel *tun;
  struct brstate *br;

  struct brctlmsg_newtun ntmsg;

  int err;

  switch ( op ) {
  case OP_BRTUNNEL_INIT:
    tun = STRUCT_FROM_BASE(struct brtunnel, brtun_init_evt, qde->qde_sub);
    br = tun->brtun_br;

    ntmsg.bcm_msg.bcm_what = BR_NEW_TUNNEL;
    memcpy(ntmsg.bcm_ports, tun->brtun_ports, sizeof(ntmsg.bcm_ports));

    if ( pthread_mutex_lock(&br->br_comm_mutex) == 0 ) {
      err = send(br->br_comm_fd[1], &ntmsg, sizeof(ntmsg), 0);
      if ( err < 0 ) {
        perror("brtunnel_evtfn: send");
      } else {
        struct brctlrsp rsp;

        err = recv(br->br_comm_fd[1], &rsp, sizeof(rsp), 0);
        if ( err < 0 ) {
          perror("brtunnel_evtfn: recv");
        } else {
          if ( rsp.bcr_sts != 0 )
            fprintf(stderr, "brtunnel: could not initialize: %d\n", rsp.bcr_sts);
        }
      }
      pthread_mutex_unlock(&br->br_comm_mutex);
    } else
      fprintf(stderr, "brtunnel: could not initialize because we couldn't unlock mutex\n");

    break;

  default:
    fprintf(stderr, "brtunnel_evtfn: unknown op %d\n", op);
  }
}

static void brtunnel_freefn(const struct shared *sh, int level) {
  struct brtunnel *tun = STRUCT_FROM_BASE(struct brtunnel, brtun_sh, sh);

  if ( level == SHFREE_NO_MORE_REFS ) {
    brtunnel_deinit(tun);
    free(tun);
  }
}

static struct brtunnel *brtunnel_alloc(struct brstate *br, int port1, int port2) {
  struct brtunnel *tun;

  SAFE_ASSERT(port1 <= port2);

  tun = malloc(sizeof(*tun));
  if ( !tun ) {
    fprintf(stderr, "brtunnel_alloc: no more space\n");
    return NULL;
  }

  SHARED_INIT(&tun->brtun_sh, brtunnel_freefn);
  tun->brtun_ports[0] = port1;
  tun->brtun_ports[1] = port2;

  tun->brtun_br = br;
  qdevtsub_init(&tun->brtun_init_evt, OP_BRTUNNEL_INIT, brtunnel_evtfn);

  return tun;
}

struct brtunnel *bridge_create_tunnel(struct brstate *br, int port1, int port2) {
  if ( port1 > port2 ) {
    return bridge_create_tunnel(br, port2, port1);
  } else {
    if ( pthread_mutex_lock(&br->br_tunnel_mutex) == 0 ) {
      struct brtunnel *ret;
      int ports_key[2] = { port1, port2 };

      HASH_FIND(brtun_ports_hh, br->br_tunnels, &ports_key, sizeof(ports_key), ret);
      if ( ret ) {
        BRTUNNEL_REF(ret);
      } else {
        ret = brtunnel_alloc(br, port1, port2);
        if ( ret ) {
          HASH_ADD(brtun_ports_hh, br->br_tunnels, brtun_ports, sizeof(ret->brtun_ports), ret);
          BRTUNNEL_REF(ret);

          BRTUNNEL_WREF(ret);
          if ( !eventloop_queue(&br->br_appstate->as_eventloop, &ret->brtun_init_evt) ) {
            BRTUNNEL_WUNREF(ret);
          }
        } else {
          fprintf(stderr, "bridge_create_tunnel: brtunnel_alloc failed\n");
        }
      }

      pthread_mutex_unlock(&br->br_tunnel_mutex);
      return ret;
    } else
      return NULL;
  }
}

static void bpr_release(struct brpermrequest *bpr) {
  if ( bpr->bpr_persona )
    PERSONA_UNREF(bpr->bpr_persona);

  free(bpr);
}

static void bridge_respond(struct brstate *br, struct brpermrequest *bpr,
                           struct appdmsg *rsp, size_t rspsz) {
  struct ethhdr rsp_eth;
  struct iphdr rsp_ip;
  struct udphdr rsp_udp;

  struct iovec iov[] = {
    { .iov_base = &rsp_eth, .iov_len = sizeof(rsp_eth) },
    { .iov_base = &rsp_ip, .iov_len = sizeof(rsp_ip) },
    { .iov_base = &rsp_udp, .iov_len = sizeof(rsp_udp) },
    { .iov_base = rsp, .iov_len = rspsz }
  };

  memcpy(rsp_eth.h_source, br->br_tap_mac, ETH_ALEN);
  memcpy(rsp_eth.h_dest, bpr->bpr_srchost, ETH_ALEN);
  rsp_eth.h_proto = htons(ETH_P_IP);

  rsp_ip.version = 4;
  rsp_ip.ihl = 5;
  rsp_ip.tos = 0x00;
  rsp_ip.tot_len = htons(sizeof(rsp_ip) + sizeof(rsp_udp) + rspsz);
  rsp_ip.id = 0xBEEF;
  rsp_ip.frag_off = htons(IP_DF);
  rsp_ip.ttl = 64;
  rsp_ip.protocol = IPPROTO_UDP;
  rsp_ip.check = 0;
  rsp_ip.saddr = br->br_tap_addr.s_addr;
  rsp_ip.daddr = bpr->bpr_srcaddr.sin_addr.s_addr;

  rsp_ip.check = htons(ip_checksum(&rsp_ip, sizeof(rsp_ip)));

  memset(&rsp_udp, 0, sizeof(rsp_udp));
  rsp_udp.uh_sport = htons(APPLIANCED_APP_PORT);
  rsp_udp.uh_dport = bpr->bpr_srcaddr.sin_port;
  rsp_udp.uh_ulen = htons(sizeof(rsp_udp) + rspsz);

  bridge_write_tap_pktv(br, iov, sizeof(iov) / sizeof(iov[0]));
}

static void bridge_respond_bpr_error(struct brstate *br, struct brpermrequest *bpr, int err) {
  struct appdmsg rsp;
  rsp.am_flags = APPD_MKFLAGS(APPD_RSP | APPD_ERROR, APPD_OPEN_APP_REQUEST);
  rsp.am_data.am_error = htonl(err);

  bridge_respond(br, bpr, &rsp, APPD_ERROR_MSG_SZ);
}

static void bridge_handle_bpr_response(struct brstate *br, struct brpermrequest *bpr) {
  if ( bpr->bpr_sts < 0 ) {
    fprintf(stderr, "bridge_handle_bpr_response: brpermrequest fails with %d\n", bpr->bpr_sts);
    bridge_respond_bpr_error(br, bpr, APPD_ERROR_SYSTEM_ERROR);
  } else {
    switch ( bpr->bpr_perm.bp_type ) {
    case BR_PERM_APPLICATION:
      if ( !bpr->bpr_persona ) {
        fprintf(stderr, "bridge_handle_bpr_response: expected bpr_persona to be filled for BR_PERM_APPLICATION\n");
        bridge_respond_bpr_error(br, bpr, APPD_ERROR_PERSONA_DOES_NOT_EXIST);
      } else {
        struct app *a = appstate_get_app_by_url_ex(br->br_appstate,
                                                   (const char *)bpr->bpr_perm.bp_data,
                                                   bpr->bpr_perm_size);
        if ( !a ) {
          fprintf(stderr, "bridge_handle_bpr_response: could not find app %.*s\n",
                  bpr->bpr_perm_size, bpr->bpr_perm.bp_data);
          bridge_respond_bpr_error(br, bpr, APPD_ERROR_APP_DOES_NOT_EXIST);
        } else {
          struct appinstance *ai = launch_app_instance(bpr->bpr_persona->p_appstate,
                                                       bpr->bpr_persona, a);
          APPLICATION_UNREF(a);
          if ( !ai ) {
            fprintf(stderr, "bridge_handle_bpr_response: could not launch app instance\n");
          } else {
            struct appdmsg rsp;
            container_release_running(&ai->inst_container, bpr->bpr_el);
            APPINSTANCE_UNREF(ai);

            fprintf(stderr, "bridge_handle_bpr_response: launched application %s\n", ai->inst_app->app_domain);

            rsp.am_flags = APPD_MKFLAGS(APPD_RSP, APPD_OPEN_APP_REQUEST);
            rsp.am_data.am_opened_app.am_family = htonl(AF_INET);
            rsp.am_data.am_opened_app.am_addr = ai->inst_container.c_ip.s_addr;
            bridge_respond(br, bpr, &rsp, APPD_OPENED_APP_RSP_SZ);
          }
        }
      }
      break;

    default:
      fprintf(stderr, "bridge_handle_bpr_response: unknown type %d\n", bpr->bpr_perm.bp_type);
      break;
    }
  }

  bpr_release(bpr);
}

void arpdesc_release(struct arpdesc *desc, size_t descsz) {
  switch ( desc->ad_container_type ) {
  case ARP_DESC_PERSONA:
    PCONN_UNREF(desc->ad_persona.ad_pconn);
    break;
  case ARP_DESC_APP_INSTANCE:
    APPINSTANCE_UNREF(desc->ad_app_instance.ad_app_instance);
    break;
  default: break;
  }
}

int bridge_describe_arp(struct brstate *br, struct in_addr *ip, struct arpdesc *desc, size_t desc_sz) {
  if ( pthread_rwlock_rdlock(&br->br_arp_mutex) == 0 ) {
    int ret = 0;
    struct arpentry *arp;
    HASH_FIND(ae_hh, br->br_arp_table, ip, sizeof(*ip), arp);
    if ( !arp ) ret = 0;
    else {
      if ( arp->ae_ctlfn ) {
        ret = arp->ae_ctlfn(arp, ARP_ENTRY_DESCRIBE, desc, desc_sz);
        if ( ret >= 0 ) ret = 1;
      }
    }
    pthread_rwlock_unlock(&br->br_arp_mutex);
    return ret;
  } else
    return -1;
}

// Permissions

#define BR_TEMP_ROUTE_PATH 1
#define BR_PERM_ROUTE_PATH 2

static int bridge_routes_path(struct brstate *br, struct pconn *pc, int which,
                              char *routes_path, int routes_path_sz) {
  int n;
  char persona_digest[PERSONA_ID_X_LENGTH + 1];
  char fingerprint_digest[EVP_MD_size(pc->pc_remote_cert_fingerprint_digest) * 2 + 1];

  if ( which == BR_TEMP_ROUTE_PATH ) {
    n = snprintf(routes_path, routes_path_sz,
                 "%s/personas/%s/sites/%s/.routes.tmp.%p",
                 br->br_appstate->as_conf_dir,
                 hex_digest_str((unsigned char *)pc->pc_persona->p_persona_id,
                                persona_digest, PERSONA_ID_LENGTH),
                 hex_digest_str((unsigned char *)pc->pc_remote_cert_fingerprint,
                              fingerprint_digest,
                                EVP_MD_size(pc->pc_remote_cert_fingerprint_digest)),
                 pc);
  } else {
    n = snprintf(routes_path, routes_path_sz,
                 "%s/personas/%s/sites/%s/routes",
                 br->br_appstate->as_conf_dir,
                 hex_digest_str((unsigned char *)pc->pc_persona->p_persona_id,
                                persona_digest, PERSONA_ID_LENGTH),
                 hex_digest_str((unsigned char *)pc->pc_remote_cert_fingerprint,
                              fingerprint_digest,
                                EVP_MD_size(pc->pc_remote_cert_fingerprint_digest)));
  }
  if ( n >= routes_path_sz ) {
    fprintf(stderr, "bridge_temp_routes_path: overflow\n");
    return -1;
  }

  return 0;
}

static FILE *bridge_open_temp_routes(struct brstate *br, struct pconn *pc) {
  char tmp_routes_path[PATH_MAX];

  if ( bridge_routes_path(br, pc, BR_TEMP_ROUTE_PATH, tmp_routes_path, sizeof(tmp_routes_path)) < 0 )
    return NULL;

  return fopen(tmp_routes_path, "wt");
}

static void bridge_cleanup_temp_routes(struct brstate *br, struct pconn *pc) {
  char tmp_routes_path[PATH_MAX];
  if ( bridge_routes_path(br, pc, BR_TEMP_ROUTE_PATH, tmp_routes_path, sizeof(tmp_routes_path)) < 0 )
    return;

  if ( unlink(tmp_routes_path) < 0 ) {
    perror("bridge_cleanup_temp_routes: unlink");
    fprintf(stderr, "while unlinking %s\n", tmp_routes_path);
  }
}

static int bridge_update_routes(struct brstate *br, struct pconn *pc) {
  char tmp_routes_path[PATH_MAX], real_routes_path[PATH_MAX];

  if ( bridge_routes_path(br, pc, BR_TEMP_ROUTE_PATH, tmp_routes_path, sizeof(tmp_routes_path)) < 0 )
    return -1;

  if ( bridge_routes_path(br, pc, BR_PERM_ROUTE_PATH, real_routes_path, sizeof(real_routes_path)) < 0 )
    return -1;

  if ( rename(tmp_routes_path, real_routes_path) < 0 ) {
    perror("bridge_update_routes: rename");
    fprintf(stderr, "while renaming %s -> %s\n", tmp_routes_path, real_routes_path);
    return -1;
  } else
    return 0;
}

static FILE *bridge_open_site_perms(struct brstate *br, struct pconn *pc) {
  char perms_path[PATH_MAX];
  char persona_digest[PERSONA_ID_X_LENGTH + 1];
  char site_digest[EVP_MD_size(pc->pc_remote_cert_fingerprint_digest) * 2 + 1];
  int n;

  FILE *ret;

  n = snprintf(perms_path, sizeof(perms_path),
               "%s/personas/%s/sites/%s/perms",
               br->br_appstate->as_conf_dir,
               hex_digest_str((unsigned char *) pc->pc_persona->p_persona_id,
                              persona_digest, PERSONA_ID_LENGTH),
               hex_digest_str((unsigned char *) pc->pc_remote_cert_fingerprint,
                              site_digest, EVP_MD_size(pc->pc_remote_cert_fingerprint_digest)));
  if ( n >= sizeof(persona_digest) ) {
    fprintf(stderr, "bridge_open_site_perms: path overflow\n");
    return NULL;
  }

  ret = fopen(perms_path, "at+");
  if ( !ret ) return NULL;

  if ( fseek(ret, 0, SEEK_SET) < 0 ) {
    perror("bridge_open_site_perms: fseek");
    fclose(ret);
    return NULL;
  }

  return ret;
}

// Site permissions live in
// <conf-dir>/personas/<persona-id>/site/<site-fingerprint>/permissions
int bridge_write_site_routes(struct brstate *br, struct pconn *pc) {
  FILE *perms, *routes;
  char perm[PATH_MAX];
  char app_addr[INET_ADDRSTRLEN];
  struct app *a, *tmp;

  routes = bridge_open_temp_routes(br, pc);
  if ( !routes ) return -1;

  perms = bridge_open_site_perms(br, pc);
  if ( !perms ) { fclose(routes); return -1; }

  SAFE_RWLOCK_RDLOCK(&br->br_appstate->as_applications_mutex);
  while ( fgets(perm, sizeof(perm), perms) ) {
    if ( validate_perm_url(perm, NULL, 0, NULL, 0) ) {
      // Check if any application has this permission
      HASH_FIND(app_hh, br->br_appstate->as_apps, perm, strlen(perm), a);

      if ( a ) {
        // Check if this application is running for this persona. If not, launch it
        struct appinstance *ai;

        ai = launch_app_instance(br->br_appstate, pc->pc_persona, a);
        if ( !ai ) {
          fprintf(stderr, "bridge_write_site_routes: skipping %s because of an error while launching\n",
                  perm);
        } else {
          int universal_access = 0;

          SAFE_MUTEX_LOCK(&a->app_mutex);
          universal_access = APP_HAS_UNIVERSAL_ACCESS(a);
          pthread_mutex_unlock(&a->app_mutex);

          if ( !universal_access )
            fprintf(routes, "%s %s\n", perm, inet_ntop(AF_INET, &ai->inst_container.c_ip,
                                                       app_addr, sizeof(app_addr)));
        }
      }
    }
  }

  HASH_ITER(app_hh, br->br_appstate->as_apps, a, tmp) {
    int universal_access = 0;
    struct appinstance *ai;

    SAFE_MUTEX_LOCK(&a->app_mutex);
    universal_access = APP_HAS_UNIVERSAL_ACCESS(a);
    pthread_mutex_unlock(&a->app_mutex);

    if ( universal_access ) {
      ai = launch_app_instance(br->br_appstate, pc->pc_persona, a);
      if ( !ai ) {
        fprintf(stderr, "bridge_write_site_routes: skipping %s because of an error while launching\n",
                a->app_domain);
      } else {
        fprintf(routes, "%s %s\n", a->app_domain, inet_ntop(AF_INET, &ai->inst_container.c_ip,
                                                            app_addr, sizeof(app_addr)));
      }
    }
  }

  pthread_rwlock_unlock(&br->br_appstate->as_applications_mutex);

  if ( ferror(perms) ) {
    fprintf(stderr, "bridge_write_site_routes: could not read permissions. Aborting\n");
    fclose(perms);
    fclose(routes);
    bridge_cleanup_temp_routes(br, pc);
  }

  // If any permission is the url of an installed application, then, add this to the route set
  fclose(perms);

  if ( bridge_update_routes(br, pc) < 0 ) {
    fclose(routes);
    return -1;
  } else {
    fclose(routes);
    return 0;
  }
}

// Bridge API

int bridge_setup_container(struct brstate *br, int port_ix,
                           struct in_addr *this_addr, const char *if_name,
                           struct arpentry *arp) {
  char cmd_buf[512], ip_addr_str[INET6_ADDRSTRLEN];
  int err, ret = 0;
  struct brctlmsg_setupns msg =
    { .bcm_msg = { .bcm_what = BR_SETUP_NAMESPACE },
      .bcm_port_ix = port_ix };
  struct brctlrsp rsp;

  memcpy(&msg.bcm_ip, this_addr, sizeof(msg.bcm_ip));

  if ( pthread_mutex_lock(&br->br_comm_mutex) == 0 ) {
    err = send(br->br_comm_fd[1], &msg, sizeof(msg), 0);
    if ( err < 0 ) {
      perror("bridge_setup_container: sendmsg");
      ret = -1;
    } else {
      err = recv(br->br_comm_fd[1], &rsp, sizeof(rsp), 0);
      if ( err < 0 ) {
        perror("bridge_setup_container: recv");
        ret = -1;
      } else {
        ret = rsp.bcr_sts;
      }
    }
    pthread_mutex_unlock(&br->br_comm_mutex);
  }

  if ( ret < 0 ) return -1;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s link set out%d name %s multicast off",
                 br->br_iproute_path, port_ix, if_name);
  if ( err >= sizeof(cmd_buf) ) goto overflow;

  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_error;

  inet_ntop(AF_INET, this_addr, ip_addr_str, sizeof(ip_addr_str));
  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s address add %s/8 broadcast 10.255.255.255 dev %s",
                 br->br_iproute_path, ip_addr_str, if_name);
  if ( err >= sizeof(cmd_buf) ) goto overflow;

  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_error;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s link set dev %s up",
                 br->br_iproute_path, if_name);
  if ( err >= sizeof(cmd_buf) ) goto overflow;

  err = system(cmd_buf);
  if ( err != 0 ) goto cmd_error;

  err = find_hw_addr(if_name, arp->ae_mac);
  if ( err < 0 ) {
    fprintf(stderr, "bridge_setup_container: could not find hardware address of %s\n", if_name);
    return -1;
  }

  memcpy(&arp->ae_ip, this_addr, sizeof(arp->ae_ip));

  return 0;

  overflow:
    fprintf(stderr, "bridge_setup_container: no space for commmand '%s'\n", cmd_buf);
    return -1;

  cmd_error:
    fprintf(stderr, "bridge_setup_container: %s failed: %d\n", cmd_buf, err);
    return -1;
}


static int bridge_try_nat(struct brstate *br, struct eventloop *el, int sz,
                           struct ethhdr *eth, struct iphdr *ip) {
  if ( pthread_rwlock_rdlock(&br->br_sctp_mutex) == 0 ) {
    struct in_addr daddr;
    struct vlannat *nat;
    int ret = 0;

    daddr.s_addr = ip->daddr;

    HASH_FIND(vn_hh, br->br_nat_table, &daddr, sizeof(daddr), nat);
    if ( nat ) {
      unsigned char *ippkt = br->br_tap_pkt + sizeof(*eth);
      int ippkt_sz = sz - sizeof(*eth);

      if ( vlannat_rewrite_pkt_to_gw(nat, (char *) ippkt, ippkt_sz) > 0 ) {
        nat->vn_on_recv_pkt(nat, ippkt, ippkt_sz);
      }
    } else
      ret = -1;

    pthread_rwlock_unlock(&br->br_sctp_mutex);
    return ret;
  } else return -1;
}

int bridge_register_vlan(struct brstate *br, struct vlannat *nat) {
  struct vlannat *old;
  if ( pthread_rwlock_wrlock(&br->br_sctp_mutex) == 0 ) {
    int ret = 0;
    HASH_FIND(vn_hh, br->br_nat_table, &nat->vn_internal, sizeof(nat->vn_internal), old);
    if ( old ) {
      fprintf(stderr, "bridge_register_vlan: already have this association\n");
      ret = -1;
    } else {
      HASH_ADD(vn_hh, br->br_nat_table, vn_internal, sizeof(nat->vn_internal), nat);
    }
    pthread_rwlock_unlock(&br->br_sctp_mutex);

    if ( ret == 0 ) {
      memcpy(&nat->vn_arpentry.ae_mac, br->br_tap_mac, sizeof(nat->vn_arpentry.ae_mac));
      return bridge_add_arp(br, &nat->vn_arpentry);
    } else
      return ret;
  } else
    return -1;
}

int bridge_unregister_vlan(struct brstate *br, struct vlannat *nat) {
  struct vlannat *old;
  if ( pthread_rwlock_wrlock(&br->br_sctp_mutex) == 0 ) {
    int ret = 0;
    HASH_FIND(vn_hh, br->br_nat_table, &nat->vn_internal, sizeof(nat->vn_internal), old);
    if ( old != nat ) {
      fprintf(stderr, "bridge_unregister_vlan: not in table\n");
      ret = -1;
    } else {
      HASH_DELETE(vn_hh, br->br_nat_table, nat);
    }
    pthread_rwlock_unlock(&br->br_sctp_mutex);

    if ( ret == 0 )
      bridge_del_arp(br, &nat->vn_arpentry);
    return ret;
  } else
    return -1;
}
