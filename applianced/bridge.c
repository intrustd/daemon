#include <openssl/err.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <net/if.h>
#include <fcntl.h>
#define _GNU_SOURCE
#include <linux/sched.h>
#include <linux/if_tun.h>

#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

#include "bridge.h"
#include "util.h"

#define OP_BRIDGE_TAP_PACKETS EVT_CTL_CUSTOM

static int bridge_setup_ns(struct brstate *br);
static int bridge_setup_main(void *br_ptr);

void bridge_clear(struct brstate *br) {
  br->br_mutexes_initialized = 0;
  br->br_iproute_path = NULL;
  br->br_uid = 0;
  br->br_gid = 0;
  br->br_comm_fd[0] = br->br_comm_fd[1] = 0;
  br->br_debug_out = NULL;
  br->br_netns = br->br_userns = br->br_tapfd = 0;
  br->br_tap_addr.s_addr = 0;
  br->br_bridge_addr.s_addr = 0;
  memset(&br->br_bridge_mac, 0, sizeof(mac_addr));
  fdsub_clear(&br->br_tap_sub);
  br->br_next_ip = 0x0100000A;
  br->br_eth_ix = 0;
}

int bridge_init(struct brstate *br, const char *iproute) {
  char ip_dbg[INET_ADDRSTRLEN], mac_dbg[32];
  int err;

  bridge_clear(br);

  br->br_uid = getuid();
  br->br_gid = getgid();

  bridge_allocate_ip(br, &br->br_bridge_addr);
  random_mac(br->br_bridge_mac);

  fprintf(stderr, "Opening bridge with IP address %s and mac %s\n",
          inet_ntop(AF_INET, &br->br_bridge_addr, ip_dbg, sizeof(ip_dbg)),
          mac_ntop(br->br_bridge_mac, mac_dbg, sizeof(mac_dbg)));

  br->br_iproute_path = iproute;

  err = pthread_rwlock_init(&br->br_arp_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "Could not initialize arp mutex: %s\n", strerror(err));
    goto error;
  }
  br->br_mutexes_initialized |= BR_ARP_MUTEX_INITIALIZED;

  err = pthread_mutex_init(&br->br_tap_write_mutex, NULL);
  if ( err != 0 ) {
    fprintf(stderr, "Could not initialize tap write mutex: %s\n", strerror(err));
    goto error;
  }
  br->br_mutexes_initialized |= BR_TAP_MUTEX_INITIALIZED;

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

  if ( br->br_mutexes_initialized & BR_TAP_MUTEX_INITIALIZED ) {
    pthread_mutex_destroy(&br->br_tap_write_mutex);
    br->br_mutexes_initialized &= ~BR_TAP_MUTEX_INITIALIZED;
  }

  if ( br->br_netns ) {
    close(br->br_netns);
    br->br_netns = 0;
  }

  if ( br->br_userns ) {
    close(br->br_userns);
    br->br_userns = 0;
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
}

static void log_tap_packet(FILE *out, char dir, const unsigned char *pkt, size_t pkt_sz) {
  size_t i;
  struct tm cur_time;
  time_t now;

  time(&now);
  localtime_r(&now, &cur_time);

  fprintf(out, "%c %02d:%02d:%02d.000000 0000", dir, cur_time.tm_hour, cur_time.tm_min, cur_time.tm_sec);
  for ( i = 0; i < pkt_sz; ++i )
    fprintf(out, " %02x", pkt[i]);
  fprintf(out, "\n");
  fflush(out);
}

static void bridge_process_arp(struct brstate *br, int size) {
}

static void bridge_process_tap_packet(struct brstate *br, int size) {
  // Check the contained protocol type
  struct ether_header *pkt = (struct ether_header *)br->br_tap_pkt;
  uint16_t ether_type = ntohs(pkt->ether_type);

  switch ( ether_type ) {
  case ETHERTYPE_ARP:
    bridge_process_arp(br, size);
    break;
  case ETHERTYPE_IP:
    //    bridge_process_ip(br, size);
    break;
  case ETHERTYPE_IPV6:
    break;
  default:
    fprintf(stderr, "Dropping ethernet packet with type %d", ether_type);
    break;
  }
}

static void bridgefn(struct eventloop *el, int op, void *arg) {
  struct brstate *br;
  struct fdevent *fdev;
  int err;

  switch ( op ) {
  case OP_BRIDGE_TAP_PACKETS:
    fdev = (struct fdevent *) arg;
    br = STRUCT_FROM_BASE(struct brstate, br_tap_sub, fdev->fde_sub);

    if ( FD_READ_PENDING(fdev) ) {
      err = read(br->br_tapfd, br->br_tap_pkt, sizeof(br->br_tap_pkt));
      if ( err < 0 ) {
        perror("bridge_tap_fn: read");
        eventloop_subscribe_fd(el, br->br_tapfd, &br->br_tap_sub);
        return;
      }

      // Attempt to process this packet
      if ( br->br_debug_out ) {
        if ( pthread_mutex_lock(&br->br_debug_mutex) == 0 ) {
          log_tap_packet(br->br_debug_out, 'I', br->br_tap_pkt, err);
          pthread_mutex_unlock(&br->br_debug_mutex);
        } else
          fprintf(stderr, "Could not log tap packet: could not lock mutex\n");
      }

      bridge_process_tap_packet(br, err);
    }

    eventloop_subscribe_fd(el, br->br_tapfd, &br->br_tap_sub);
    break;
  default:
    fprintf(stderr, "bridge_tap_fn: Unknown op %d\n", op);
  };
}

void bridge_start(struct brstate *br, struct eventloop *el) {
  fdsub_init(&br->br_tap_sub, el, br->br_tapfd, OP_BRIDGE_TAP_PACKETS, bridgefn);

  FDSUB_SUBSCRIBE(&br->br_tap_sub, FD_SUB_READ | FD_SUB_READ_OOB);
  eventloop_subscribe_fd(el, br->br_tapfd, &br->br_tap_sub);
}

int bridge_write_tap_pkt(struct brstate *br, const unsigned char *tap_pkt, uint8_t tap_sz) {
  int err;

  if ( pthread_mutex_lock(&br->br_tap_write_mutex) != 0 ) {
    errno = EBUSY;
    return -1;
  }

  err = write(br->br_tapfd, tap_pkt, tap_sz);
  if ( err < 0 ) {
    int old_err = errno;
    perror("bridge_write_tap_pkt: write");
    err = old_err;
  }

  if ( err == 0 && br->br_debug_out ) {
    if ( pthread_mutex_lock(&br->br_debug_mutex) == 0 ) {
      // Output raw tap pkt
      log_tap_packet(br->br_debug_out, 'O', tap_pkt, tap_sz);
      pthread_mutex_unlock(&br->br_debug_mutex);
    } else
      fprintf(stderr, "bridge_write_tap_pkt: Skipping debug packet because the mutex could not be locked\n");
  } else
    fprintf(stderr, "bridge_write_tap_pkt: Skipping packet because there was en error writing\n");

  pthread_mutex_unlock(&br->br_tap_write_mutex);

  if ( err != 0 ) {
    errno = err;
    return -1;
  } else return 0;
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
  new_ip->s_addr = __sync_fetch_and_add(&br->br_next_ip, 1);
}

void bridge_allocate(struct brstate *br, struct in_addr *new_ip, int *new_eth_ix) {
  bridge_allocate_ip(br, new_ip);
  *new_eth_ix = __sync_fetch_and_add(&br->br_eth_ix, 1);
}

static void setup_namespace_users(uid_t uid, gid_t gid) {
  FILE *deny_setgroups, *gid_map, *uid_map;
  int err;

  deny_setgroups = fopen("/proc/self/setgroups", "wt");
  if ( !deny_setgroups ) {
    perror("Could not open /proc/self/setgroups");
    exit(1);
  }
  fprintf(deny_setgroups, "deny");
  fclose(deny_setgroups);

  gid_map = fopen("/proc/self/gid_map", "wt");
  if ( !gid_map ) {
    perror("Could not open /proc/self/gid_map");
    exit(1);
  }
  fprintf(gid_map, "0 %d 1\n", gid);
  fclose(gid_map);

  uid_map = fopen("/proc/self/uid_map", "wt");
  if ( !uid_map ) {
    perror("Could not open /proc/self/uid_map");
    exit(1);
  }
  fprintf(uid_map, "0 %d 1\n", uid);
  fclose(uid_map);

  err = setreuid(0, 0);
  if ( err < 0 ) {
    perror("setup_namespace_users: setreuid(0, 0)");
    exit(1);
  }

  err = setregid(0, 0);
  if ( err < 0 ) {
    perror("setup_namespace_users: setregid(0, 0)");
    exit(1);
  }
}

static int bridge_setup_tap(struct brstate *br, char *tap_nm) {
  int fd, err;
  struct ifreq ifr;

  fd = open("/dev/net/tun", O_RDWR);
  if ( fd < 0 ) {
    perror("bridge_setup_tap: open(/dev/net/tun)");
    exit(4);
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

  err = ioctl(fd, TUNSETIFF, (void *) &ifr);
  if ( err < 0 ) {
    perror("bridge_setup_tap: ioctl(TUNSETIFF)");
    exit(5);
  }

  strncpy(tap_nm, ifr.ifr_name, IFNAMSIZ);

  return fd;
}

static void bridge_create_bridge(struct brstate *br, const char *tap_nm) {
  char cmd_buf[512];
  int err;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s link add bridge type bridge", br->br_iproute_path);
  if ( err >= sizeof(cmd_buf) ) goto nospc;
  err = system(cmd_buf);
  if ( err != 0 ) goto cmdfailed;

  err = snprintf(cmd_buf, sizeof(cmd_buf), "%s link set dev lo up", br->br_iproute_path);
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

  return;

 cmdfailed:
  fprintf(stderr, "bridge_create_bridge: '%s' failed with %d\n", cmd_buf, err);
  exit(err);

 nospc:
  fprintf(stderr, "bridge_create_bridge: Not enough space in cmd_buf\n");
  exit(3);
}

static int bridge_setup_main(void *br_ptr) {
  struct brstate *br = (struct brstate *)br_ptr;
  char tap_nm[IFNAMSIZ];
  int fds[3], tap, netns, userns, err;

  close(br->br_comm_fd[1]);

  setup_namespace_users(br->br_uid, br->br_gid);
  fprintf(stderr, "Setup namespace users\n");

  tap = bridge_setup_tap(br, tap_nm);
  fprintf(stderr, "Created tap device %s\n", tap_nm);

  bridge_create_bridge(br, tap_nm);

  netns = open("/proc/self/ns/net", 0);
  if ( netns < 0 )
    perror("open(/proc/self/ns/net)");

  userns = open("/proc/self/ns/user", 0);
  if ( userns < 0 )
    perror("open(/proc/self/ns/user)");

  fds[0] = netns;
  fds[1] = userns;
  fds[2] = tap;

  err = send_fd(br->br_comm_fd[0], sizeof(fds) / sizeof(fds[0]), fds);
  if ( err < 0 ) {
    perror("bridge_setup_main: send_fd");
    return 1;
  }

  close(br->br_comm_fd[0]);
  return 0;
}

static int bridge_setup_ns(struct brstate *br) {
  char stack[8192];
  int err, new_proc, ns_fds[3];

  fprintf(stderr, "bridge_setup_ns: stack is %p\n", stack);

  err = socketpair(AF_UNIX, SOCK_DGRAM, 0, br->br_comm_fd);
  if ( err < 0 ) {
    perror("bridge_setup_ns: socketpair");
    return -1;
  }

  new_proc =
    clone(&bridge_setup_main, stack + sizeof(stack),
          CLONE_NEWUSER | CLONE_NEWNET | CLONE_VFORK, br);
  if ( new_proc == -1 ) {
    perror("bridge_setup_ns: clone");
    return -1;
  }

  close(br->br_comm_fd[0]);
  br->br_comm_fd[0] = 0;

  err = recv_fd(br->br_comm_fd[1], sizeof(ns_fds) / sizeof(ns_fds[0]), ns_fds);
  if ( err < 0 ) {
    fprintf(stderr, "bridge_setup_ns: could not fetch namespace fds\n");
    return -1;
  }

  br->br_netns = ns_fds[0];
  br->br_userns = ns_fds[1];
  br->br_tapfd = ns_fds[2];

  close(br->br_comm_fd[1]);
  br->br_comm_fd[1] = 0;

  fprintf(stderr, "Got net ns(%d), user ns(%d), and tap fd(%d)\n",
          br->br_netns, br->br_userns, br->br_tapfd);

  fcntl(br->br_netns, F_SETFD, FD_CLOEXEC);
  fcntl(br->br_userns, F_SETFD, FD_CLOEXEC);
  fcntl(br->br_tapfd, F_SETFD, FD_CLOEXEC);

  if ( set_socket_nonblocking(br->br_tapfd) < 0 )
    fprintf(stderr, "Could not set TAP non blocking\n");

  return 0;
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
