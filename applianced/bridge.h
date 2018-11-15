#ifndef __appliance_bridge_H__
#define __appliance_bridge_H__

#include <stdio.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <uthash.h>

#include "event.h"

#define BR_CAPABILITY_SIZE 256
#define PERSONA_ID_LENGTH   32
#define APP_URL_MAX 1024

typedef unsigned char mac_addr[ETH_ALEN];

#define ARP_DESC_PERSONA 1
#define ARP_DESC_APP_INSTANCE 2
struct pconn;
struct appinstance;
struct arpdesc {
  int ad_container_type;
  union {
    struct {
      char ad_persona_id[PERSONA_ID_LENGTH];
      struct pconn *ad_pconn;
    } ad_persona;
    struct {
      char ad_persona_id[PERSONA_ID_LENGTH];
      char ad_app_url[APP_URL_MAX];
      struct appinstance *ad_app_instance;
    } ad_app_instance;
  };
};

void arpdesc_release(struct arpdesc *desc, size_t descsz);

struct container;

struct arpentry;
struct brpermrequest;
typedef int(*aectlfn)(struct arpentry*, int, void *, ssize_t);

#define ARP_ENTRY_CHECK_PERMISSION 1
#define ARP_ENTRY_DESCRIBE 2

struct arpentry {
  mac_addr       ae_mac;
  struct in_addr ae_ip;
  UT_hash_handle ae_hh;
  aectlfn        ae_ctlfn;
};

// we intercept sctp packets
struct sctpentry;
typedef void(*pktfn)(struct sctpentry *, const void*, size_t);
struct sctpentry {
  UT_hash_handle se_hh;
  struct sockaddr_in se_source;
  pktfn se_on_packet;
};

// brtunnel -- defines a two-way tunnel between two running containers.
//
// As long as this object is referenced, the two containers can talk
//
// You get these objects using bridge_create_tunnel
//
// Invariant: port[0] <= port[1]
struct brtunnel {
  struct shared brtun_sh;

  UT_hash_handle brtun_ports_hh;

  int brtun_ports[2];

  struct brstate *brtun_br;
  struct qdevtsub brtun_init_evt;
};

#define BRTUNNEL_REF(tun) SHARED_REF(&(tun)->brtun_sh)
#define BRTUNNEL_UNREF(tun) SHARED_UNREF(&(tun)->brtun_sh)
#define BRTUNNEL_WREF(tun) SHARED_WREF(&(tun)->brtun_sh)
#define BRTUNNEL_WUNREF(tun) SHARED_WUNREF(&(tun)->brtun_sh)

#define BR_PERM_APPLICATION 1

#define BPR_ERR_PERMISSION_DENIED 401
#define BPR_ERR_INTERNAL 500

struct brperm {
  // One of the BR_PERM_* constants
  int bp_type;
  unsigned char bp_data[];
};

struct brpermrequest {
  struct eventloop *bpr_el;
  struct brstate *bpr_bridge;
  struct persona *bpr_persona;
  void *bpr_user_data;

  // Handlers should use this event to asynchronously begin event
  // processing, if the request is going to take a long time.
  struct qdevtsub bpr_start_event;
  // Handlers should invoke this event on completion
  struct qdevtsub bpr_finished_event;

  mac_addr bpr_srchost;
  struct sockaddr_in bpr_srcaddr;

  // Handlers should fill this with 0, if the permission has been
  // granted, or a negative response code (BPR_ERR_*) otherwise, before calling
  // bpr_finished_event.
  int bpr_sts;

  // All outstanding requests are in the br_outstanding_checks hash table
  UT_hash_handle bpr_hh;

  int bpr_perm_size; // The total size of the permission below
  struct brperm bpr_perm;
};

struct brstate {
  struct appstate *br_appstate;

  uint32_t br_mutexes_initialized;

  const char *br_iproute_path;
  const char *br_ebroute_path;

  uid_t br_uid, br_user_uid;
  gid_t br_gid, br_user_gid;
  int   br_comm_fd[2];

  char br_capability[BR_CAPABILITY_SIZE];

  pthread_mutex_t br_debug_mutex;
  FILE *br_debug_out;

  // Net namespace and user namespace file descriptors
  int br_netns, br_userns, br_tapfd;
  struct in_addr br_bridge_addr;
  mac_addr br_bridge_mac;

  pthread_mutex_t br_tap_write_mutex;
  struct fdsub br_tap_sub;

  pthread_rwlock_t br_arp_mutex;
  struct arpentry *br_arp_table;
  struct brpermrequest *br_outstanding_checks; // protected by arp mutex

  pthread_rwlock_t br_sctp_mutex;
  struct sctpentry *br_sctp_table;

  pthread_mutex_t br_tunnel_mutex;
  struct brtunnel *br_tunnels;

  // Only access via bridge_allocate
  uint32_t br_next_ip, br_eth_ix;

  unsigned char br_tap_pkt[2048];
};

#define BR_DEBUG_MUTEX_INITIALIZED  0x1
#define BR_ARP_MUTEX_INITIALIZED    0x2
#define BR_TAP_MUTEX_INITIALIZED    0x4
#define BR_SCTP_MUTEX_INITIALIZED   0x8
#define BR_TUNNEL_MUTEX_INITIALIZED 0x10

void bridge_clear(struct brstate *br);
int bridge_init(struct brstate *br, struct appstate *as, uid_t user_uid, gid_t user_gid, const char *iproute_path, const char *ebroute_path);
void bridge_release(struct brstate *br);

void bridge_start(struct brstate *br, struct eventloop *el);
void bridge_enable_debug(struct brstate *br, const char *path);

void bridge_allocate_ip(struct brstate *br, struct in_addr *new_ip);
void bridge_allocate(struct brstate *br, struct in_addr *new_ip, int *new_eth_ix);

int bridge_add_arp(struct brstate *br, struct arpentry *new_arp);
int bridge_del_arp(struct brstate *br, struct arpentry *old_arp);

int bridge_register_sctp(struct brstate *br, struct sctpentry *se);
int bridge_unregister_sctp(struct brstate *br, struct sctpentry *se);

int bridge_write_from_foreign_pkt(struct brstate *br, struct container *dst,
                                  const struct sockaddr *sa, socklen_t sa_sz,
                                  const unsigned char *tap_pkt, uint16_t tap_sz);
int bridge_write_tap_pkt(struct brstate *br, const unsigned char *tap_pkt, uint16_t tap_sz);
int bridge_write_tap_pktv(struct brstate *br, const struct iovec *iov, int iovcnt);

void random_mac(unsigned char *mac);
char *mac_ntop(const unsigned char *mac, char *str, int str_sz);

// Container utilities
int bridge_setup_root_uid_gid(struct brstate *br);
int bridge_set_up_networking(struct brstate *br);
int bridge_create_veth_to_ns(struct brstate *br, int port_ix, int this_netns,
                             struct in_addr *this_ip, const char *if_name,
                             struct arpentry *arp);
int bridge_disconnect_port(struct brstate *br, int port, struct arpentry *arp);

int bridge_describe_arp(struct brstate *br, struct in_addr *ip, struct arpdesc *desc, size_t desc_sz);

struct brtunnel *bridge_create_tunnel(struct brstate *br, int port1, int port2);

int bridge_mark_as_admin(struct brstate *br, int port_ix, struct arpentry *arp);

// Ask to write out the routes for the given site. If the site
// permissions do not exist, this will create the site permissions
// directory.
//
// pc should be locked
struct pconn;
int bridge_write_site_routes(struct brstate *br, struct pconn *pc);

#endif
