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

struct arpentry {
  mac_addr       ae_mac;
  struct in_addr ae_ip;
  UT_hash_handle ae_hh;
};

struct brstate {
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
  struct in_addr br_tap_addr, br_bridge_addr;
  mac_addr br_bridge_mac;

  pthread_mutex_t br_tap_write_mutex;
  struct fdsub br_tap_sub;

  pthread_rwlock_t br_arp_mutex;
  struct arpentry *br_arp_table;

  // Only access via bridge_allocate
  uint32_t br_next_ip, br_eth_ix;

  unsigned char br_tap_pkt[2048];
};

#define BR_DEBUG_MUTEX_INITIALIZED 0x1
#define BR_ARP_MUTEX_INITIALIZED   0x2
#define BR_TAP_MUTEX_INITIALIZED   0x4

void bridge_clear(struct brstate *br);
int bridge_init(struct brstate *br, const char *iproute_path);
void bridge_release(struct brstate *br);

void bridge_start(struct brstate *br, struct eventloop *el);
void bridge_enable_debug(struct brstate *br, const char *path);

void bridge_allocate_ip(struct brstate *br, struct in_addr *new_ip);
void bridge_allocate(struct brstate *br, struct in_addr *new_ip, int *new_eth_ix);

int bridge_write_tap_pkt(struct brstate *br, const unsigned char *tap_pkt, uint8_t tap_sz);

void random_mac(unsigned char *mac);
char *mac_ntop(const unsigned char *mac, char *str, int str_sz);

#endif
