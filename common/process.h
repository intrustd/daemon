#ifndef __intrustd_process_H__
#define __intrustd_process_H__

#include <stdlib.h>
#include <stdio.h>

#include "event.h"

typedef void(*argfreefn)(void *);
struct pssubopts {
  uint32_t pso_flags;

  int pso_stdout, pso_stderr, pso_stdin;
  int pso_stdout_read, pso_stderr_read, pso_stdin_write;

  char *pso_command;
  argfreefn pso_command_free;

  size_t pso_argc, pso_args_size;
  char **pso_args;
  argfreefn *pso_arg_free;

  size_t pso_envc, pso_envs_size;
  char **pso_env;
};

#define PSSUBOPT_FLAG_ERROR 0x00000001

#define PSSUB_STDERR STDERR_FILENO
#define PSSUB_STDIN STDIN_FILENO
#define PSSUB_STDOUT STDOUT_FILENO

#define pssubopts_error(pso) ((pso)->pso_flags & PSSUBOPT_FLAG_ERROR)

void pssubopts_init(struct pssubopts *pso);
void pssubopts_release(struct pssubopts *pso);
int pssubopts_pipe_to_file(struct pssubopts *pso, int which, FILE *f);
int pssubopts_pipe_to_fd(struct pssubopts *pso, int which, int fd);

void pssubopts_set_command(struct pssubopts *pso, const char *cmd, argfreefn fn);
int pssubopts_push_arg(struct pssubopts *pso, const char *arg, argfreefn fn);
int pssubopts_push_env(struct pssubopts *pso, const char *var, const char *val);

struct pssub {
  int ps_op;
  evtctlfn ps_ctl;

  int ps_stdin, ps_stdout, ps_stderr;
  struct fdsub ps_stdin_sub, ps_stdout_sub, ps_stderr_sub;

  pid_t ps_which;
  int ps_status;

  struct qdevtsub ps_on_complete;

  DLIST(struct pssub) ps_list;
};

#define PSE_STDIN_CAN_WRITE 0x00000001
#define PSE_STDOUT_CAN_READ 0x00000002
#define PSE_STDERR_CAN_READ 0x00000004
#define PSE_DONE            0x00000008

struct psevent {
  struct pssub *pse_sub;
  uint32_t pse_what;
  int pse_sts;
};

void pssub_init(struct pssub *ps, int op, evtctlfn fn);
// Only release this when you *know* the process has completed or isn't running
void pssub_release(struct pssub *ps);
void pssub_resubscribe(struct eventloop *el, struct pssub *ps);
int pssub_run_from_opts(struct eventloop *el, struct pssub *ps, struct pssubopts *opts);
int pssub_detach_attach(struct eventloop *el, struct pssub *det, struct pssub *att, pid_t p);
int pssub_detach(struct eventloop *el, struct pssub *ps);
int pssub_attach(struct eventloop *el, struct pssub *ps, pid_t p);

#endif
