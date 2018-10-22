#ifndef __appliancectl_commands_H__
#define __appliancectl_commands_H__

#include <stdlib.h>
#include <stdint.h>

// Utilities

const char *kite_error_code_str(uint16_t code);
const char *kite_entity_str(uint16_t entity);
const char *kite_operation_str(uint16_t otype);

int display_stork_response(char *buf, int size, const char *success_msg);
int mk_api_socket();

int send_with_fds(int sk, const void *buf, size_t bufsz, int flags,
                  int *fds, int nfds);

// Commands
int create_persona(int argc, char **argv);
int list_personas(int argc, char **argv);

int join_flock(int argc, char **argv);
int list_flocks(int argc, char **argv);

int register_app(int argc, char **argv);

//int get_container(int argc, char **argv);
int run_in_container(int argc, char **argv);

#endif
