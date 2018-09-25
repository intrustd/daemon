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

typedef unsigned char mac_addr[ETH_ALEN];

struct container;

struct arpentry;
struct brpermrequest;
typedef void(*aepermfn)(struct arpentry*, struct brpermrequest*);
struct arpentry {
  mac_addr       ae_mac;
  struct in_addr ae_ip;
  UT_hash_handle ae_hh;
  aepermfn       ae_permfn;
};

// we intercept sctp packets
struct sctpentry;
typedef void(*pktfn)(struct sctpentry *, const void*, size_t);
struct sctpentry {
  UT_hash_handle se_hh;
  struct sockaddr_in se_source;
  pktfn se_on_packet;
};

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

  uid_t br_uid;
  gid_t br_gid;
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

  // Only access via bridge_allocate
  uint32_t br_next_ip, br_eth_ix;

  unsigned char br_tap_pkt[2048];
};

#define BR_DEBUG_MUTEX_INITIALIZED 0x1
#define BR_ARP_MUTEX_INITIALIZED   0x2
#define BR_TAP_MUTEX_INITIALIZED   0x4
#define BR_SCTP_MUTEX_INITIALIZED  0x8

void bridge_clear(struct brstate *br);
int bridge_init(struct brstate *br, struct appstate *as, const char *iproute_path);
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

#endif
