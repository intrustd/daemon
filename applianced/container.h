#ifndef __appliance_container_H__
#define __appliance_container_H__

#include <sys/socket.h>
#include <netinet/in.h>

#include "event.h"
#include "bridge.h"

#define CONTAINER_MAX_ARGC 255
#define CONTAINER_MAX_ENVC 255
#define CONTAINER_TIMEOUT (10 * 60000) // Ten minutes

struct container;
typedef int(*containerctlfn)(struct container *, int, void *, ssize_t);

// Return negative on error, 0 on success
#define CONTAINER_CTL_GET_INIT_PATH     1
// ssize parameter is number of arguments maximum. Should return number of arguments
#define CONTAINER_CTL_GET_ARGS          2
#define CONTAINER_CTL_GET_HOSTNAME      3
#define CONTAINER_CTL_RELEASE_INIT_PATH 4
// pointer parameter is arg, ssize_t param is index
#define CONTAINER_CTL_RELEASE_ARG       5
#define CONTAINER_CTL_RELEASE_HOSTNAME  6

#define CONTAINER_CTL_ON_SHUTDOWN       7

// The bridge wants to know if this container should have permission
// to access the given resource. The argument is a heap allocated
// 'struct brpermrequest'. The permission should be filled in
// (asynchronously), and the results communicated back by firing the
// event.
#define CONTAINER_CTL_CHECK_PERMISSION 8

#define CONTAINER_CTL_DO_SETUP         9

struct container {
  struct brstate *c_bridge;
  pthread_mutex_t c_mutex;

  // <0 if the container is not running
  pid_t           c_init_process;
  // <0 if container is not running
  int             c_init_comm;

  int             c_bridge_port;
  struct in_addr  c_ip;
  // Only valid if c_init_process != 0
  mac_addr        c_mac;
  containerctlfn  c_control;

  // If >0 then, some thing needs this container running
  int             c_running_refs;

  // After the last reference is released, this timer is set
  struct timersub c_timeout;

  struct arpentry c_arp_entry;
};

void container_clear(struct container *c);
int container_init(struct container *c, struct brstate *br, containerctlfn cfn);
void container_release(struct container *c);

// Negative on error, 0 on succes, and 1 on success, if the container was launched
int container_ensure_running(struct container *c, struct eventloop *el);
int container_release_running(struct container *c, struct eventloop *el);

#define CONTAINER_EXEC_WAIT_FOR_KITE 0x00000001

int container_execute(struct container *c, uint32_t exec_flags, const char *path,
                      const char **argv, const char **envp);

#endif
