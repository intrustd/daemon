#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>

#include "process.h"

#define OP_PS_STDIN EVT_CTL_CUSTOM
#define OP_PS_STDOUT (EVT_CTL_CUSTOM + 1)
#define OP_PS_STDERR (EVT_CTL_CUSTOM + 2)
#define OP_PS_COMPLETE (EVT_CTL_CUSTOM + 3)

static void psevtfn(struct eventloop *el, int op, void *arg);

void pssubopts_init(struct pssubopts *pso) {
  pso->pso_flags = 0;
  pso->pso_stdin = pso->pso_stdout = pso->pso_stderr = -1;
  pso->pso_stdin_write = pso->pso_stdout_read = pso->pso_stderr_read = -1;
  pso->pso_command = NULL;
  pso->pso_command_free = NULL;
  pso->pso_argc = 0;
  pso->pso_args_size = 0;
  pso->pso_args = NULL;
  pso->pso_arg_free = NULL;
  pso->pso_envc = 0;
  pso->pso_envs_size = 0;
  pso->pso_env = NULL;
}

void pssubopts_release(struct pssubopts *pso) {
  size_t i;

  if ( pso->pso_stdin >= 0 )
    close(pso->pso_stdin);
  if ( pso->pso_stdout >= 0 )
    close(pso->pso_stdout);
  if ( pso->pso_stderr >= 0 )
    close(pso->pso_stderr);

  if ( pso->pso_stdin_write >= 0 )
    close(pso->pso_stdin_write);
  if ( pso->pso_stdout_read >= 0 )
    close(pso->pso_stdout_read);
  if ( pso->pso_stderr_read >= 0 )
    close(pso->pso_stderr_read);

  if ( pso->pso_command_free )
    pso->pso_command_free(pso->pso_command);

  for ( i = 0; i < pso->pso_argc; ++i ) {
    if ( pso->pso_arg_free[i] )
      pso->pso_arg_free[i](pso->pso_args[i]);
  }

  for ( i = 0; i < pso->pso_envc; ++i ) {
    free(pso->pso_env[i]);
  }

  if ( pso->pso_arg_free ) {
    free(pso->pso_arg_free);
  }
  if ( pso->pso_args ) {
    free(pso->pso_args);
  }
  if ( pso->pso_env ) {
    free(pso->pso_env);
  }
}

int pssubopts_pipe_to_file(struct pssubopts *pso, int which, FILE *f) {
  int *tgt, *tgt_other;
  int fd = fileno(f), new_fd, old_fd;
  if ( fd < 0 ) {
    if ( errno != EBADF )
      perror("pssubopts: file_no");
    return -1;
  }

  switch ( which ) {
  case PSSUB_STDERR: tgt = &pso->pso_stderr; tgt_other = &pso->pso_stderr_read; break;
  case PSSUB_STDOUT: tgt = &pso->pso_stdout; tgt_other = &pso->pso_stdout_read; break;
  case PSSUB_STDIN:  tgt = &pso->pso_stdin;  tgt_other = &pso->pso_stdin_write; break;
  default: return -1;
  }

  old_fd = *tgt;
  new_fd = dup(fd);
  if ( new_fd < 0 ) {
    perror("pssubopts_pipe_to_file: dup");
    return -1;
  }

  if ( old_fd >= 0 ) close(old_fd);
  if ( *tgt_other >= 0 )
    close(*tgt_other);

  *tgt = new_fd;
  *tgt_other = -1;

  return 0;
}

int pssubopts_pipe_to_fd(struct pssubopts *pso, int which, int fd) {
  int *tgt, *tgt_other;

  switch ( which ) {
  case PSSUB_STDERR: tgt = &pso->pso_stderr; tgt_other = &pso->pso_stderr_read; break;
  case PSSUB_STDOUT: tgt = &pso->pso_stdout; tgt_other = &pso->pso_stdout_read; break;
  case PSSUB_STDIN:  tgt = &pso->pso_stdin;  tgt_other = &pso->pso_stdin_write; break;
  default: return -1;
  }

  if ( *tgt == fd ) return 0;

  if ( *tgt_other ) close(*tgt_other);
  if ( *tgt ) close(*tgt);

  *tgt_other = -1;
  *tgt = fd;

  return 0;
}

void pssubopts_set_command(struct pssubopts *pso, const char *cmd, argfreefn freefn) {
  if ( pso->pso_command_free )
    pso->pso_command_free(pso->pso_command);

  pso->pso_command = (char *) cmd;
  pso->pso_command_free = freefn;
}

int pssubopts_push_arg(struct pssubopts *pso, const char *arg, argfreefn fn) {
  if ( pssubopts_error(pso) ) return -1;

  assert(pso->pso_argc <= pso->pso_args_size);
  if ( (pso->pso_argc + 1) >= pso->pso_args_size ) {
    size_t newsz;
    char **newargs;
    argfreefn *newfrees;

    newsz = pso->pso_args_size * 2;
    if ( newsz == 0 )
      newsz = 4;
    newargs = realloc(pso->pso_args, sizeof(*newargs) * (newsz + 1));
    if ( !newargs ) {
      pso->pso_flags |= PSSUBOPT_FLAG_ERROR;
      return -1;
    }
    pso->pso_args = newargs;

    newfrees = realloc(pso->pso_arg_free, sizeof(*newfrees) * newsz);
    if ( !newfrees ) {
      pso->pso_flags |= PSSUBOPT_FLAG_ERROR;
      return -1;
    }
    pso->pso_arg_free = newfrees;

    pso->pso_args_size = newsz;
  }

  assert((pso->pso_argc + 1) < pso->pso_args_size);
  pso->pso_args[pso->pso_argc] = (char *)arg;
  pso->pso_arg_free[pso->pso_argc] = fn;
  pso->pso_argc ++;
  pso->pso_args[pso->pso_argc] = NULL;

  return -1;
}

int pssubopts_push_env(struct pssubopts *pso, const char *var, const char *val) {
  char *env;
  int envoffs = 0;

  if ( pssubopts_error(pso) ) return -1;

  env  = malloc(strlen(var) + strlen(val) + 2);
  if ( ! env ) {
    return -1;
  }

  memcpy(env, var, strlen(var));
  envoffs += strlen(var);

  env[envoffs++] = '=';

  memcpy(env + envoffs, val, strlen(val));
  envoffs += strlen(val);
  env[envoffs] = '\0';

  assert(pso->pso_envc <= pso->pso_envs_size);
  if ( (pso->pso_envc + 1) >= pso->pso_envs_size ) {
    char **newenv;
    size_t newsz;

    newsz = pso->pso_envs_size * 2;
    if ( newsz == 0 )
      newsz = 4;

    newenv = realloc(pso->pso_env, sizeof(*newenv) * newsz);
    if ( !newenv ) {
      pso->pso_flags |= PSSUBOPT_FLAG_ERROR;
      return -1;
    }
    pso->pso_env = newenv;
    pso->pso_envs_size = newsz;
  }

  assert((pso->pso_envc + 1) < pso->pso_envs_size);
  pso->pso_env[pso->pso_envc] = (char *)env;
  pso->pso_envc++;

  return -1;
}

// pssub


void pssub_init(struct pssub *ps, int op, evtctlfn fn) {
  ps->ps_op  = op;
  ps->ps_ctl = fn;
  ps->ps_stdin = ps->ps_stdout = ps->ps_stderr = -1;
  qdevtsub_init(&ps->ps_on_complete, OP_PS_COMPLETE, psevtfn);
//  fdsub_init(&ps->ps_stdin_sub,  el, OP_PS_STDIN, fn);
//  fdsub_init(&ps->ps_stdout_sub, el, OP_PS_STDOUT, fn);
//  fdsub_init(&ps->ps_stderr_sub, el, OP_PS_STDERR, fn);
  ps->ps_which = -1;
  DLIST_ENTRY_CLEAR(&ps->ps_list);
}

void pssub_release(struct pssub *ps) {
  if ( ps->ps_stdin >= 0 )
    close(ps->ps_stdin);
  if ( ps->ps_stdout >= 0 )
    close(ps->ps_stdout);
  if ( ps->ps_stderr >= 0 )
    close(ps->ps_stderr);

  ps->ps_which = -1;
}

int pssub_attach(struct eventloop *el, struct pssub *ps, pid_t p) {
  return pssub_detach_attach(el, NULL, ps, p);
}

int pssub_detach(struct eventloop *el, struct pssub *ps) {
  return pssub_detach_attach(el, ps, NULL, 0);
}

int pssub_detach_attach(struct eventloop *el, struct pssub *det, struct pssub *att, pid_t p) {
  if ( pthread_mutex_lock(&el->el_ps_mutex) == 0 ) {
    int ret = 0;

    if ( det && det->ps_which > 0 ) {
      DLIST_REMOVE(&el->el_processes, ps_list, det);
      det->ps_which = -1;
      det->ps_status = -1;
    } else if ( det )
      ret = -1;

    if ( att && att->ps_which < 0 && ret == 0 ) {
      att->ps_which = p;
      att->ps_status = -1;

      DLIST_INSERT(&el->el_processes, ps_list, att);
    } else
      ret = -1;

    pthread_mutex_unlock(&el->el_ps_mutex);
    return ret;
  } else
    return -1;
}

int pssub_run_from_opts(struct eventloop *el, struct pssub *ps, struct pssubopts *opts) {
  if ( pthread_mutex_lock(&el->el_ps_mutex) == 0 ) {
    int ret = 0;
    pid_t new_child;

    if ( DLIST_ENTRY_IN_LIST(&el->el_processes, ps_list, ps) ) {
      ret = -1;
    } else {
      new_child = fork();
      if ( new_child < 0 ) {
        perror("pssub_run_from_opts: fork");
        ret = -1;
      } else if ( new_child == 0 ) {
        int err, i;

        // Set all environment variables
        for ( i = 0; i < opts->pso_envc; ++i ) {
          if ( putenv(opts->pso_env[i]) < 0 ) {
            perror("pssub_run_from_opts: putenv");
            exit(256);
          }
        }

        if ( opts->pso_stdin_write >= 0 ) close(opts->pso_stdin_write);
        if ( opts->pso_stdout_read >= 0 ) close(opts->pso_stdout_read);
        if ( opts->pso_stderr_read >= 0 ) close(opts->pso_stderr_read);

        if ( opts->pso_stdin >= 0 ) {
          err = dup2(opts->pso_stdin, STDIN_FILENO);
          if ( err < 0 ) {
            perror("pssub_run_from_opts: dup2 STDIN_FILENO");
            goto child_error;
          }
          close(opts->pso_stdin);
        }

        if ( opts->pso_stderr >= 0 ) {
          err = dup2(opts->pso_stderr, STDERR_FILENO);
          if ( err < 0 ) {
            perror("pssub_run_from_opts: dup2 STDERR_FILENO");
            goto child_error;
          }
          close(opts->pso_stderr);
        }

        if ( opts->pso_stdout >= 0 ) {
          err = dup2(opts->pso_stdout, STDOUT_FILENO);
          if ( err < 0 ) {
            perror("pssub_run_from_opts: dup2 STDOUT_FILENO");
            goto child_error;
          }
          close(opts->pso_stdout);
        }

        execvp(opts->pso_command, opts->pso_args);
        perror("pssub_run_from_opts: exec");
      child_error:
        exit(EXIT_FAILURE);
      } else {
        if ( opts->pso_stdin_write >= 0 ) {
          ps->ps_stdin = opts->pso_stdin_write;
          opts->pso_stdin_write = -1;
        }

        if ( opts->pso_stdout_read >= 0 ) {
          ps->ps_stdout = opts->pso_stdout_read;
          opts->pso_stdout_read = -1;
        }

        if ( opts->pso_stderr_read >= 0 ) {
          ps->ps_stderr = opts->pso_stderr_read;
          opts->pso_stderr_read = -1;
        }

        ps->ps_which = new_child;

        DLIST_INSERT(&el->el_processes, ps_list, ps);
      }
    }
    pthread_mutex_unlock(&el->el_ps_mutex);
    return ret;
  } else
    return -1;
}

static void psevtfn(struct eventloop *el, int op, void *arg) {
  struct qdevent *qde;
  struct pssub *sub;
  struct psevent pse;

  switch ( op ) {
  case OP_PS_STDIN:
  case OP_PS_STDOUT:
  case OP_PS_STDERR:
    break;

  case OP_PS_COMPLETE:
    qde = arg;
    sub = STRUCT_FROM_BASE(struct pssub, ps_on_complete, qde->qde_sub);
    pse.pse_sub = sub;
    pse.pse_what = PSE_DONE;
    pse.pse_sts = sub->ps_status;
    sub->ps_ctl(el, sub->ps_op, &pse);
    break;

  default:
    fprintf(stderr, "psevtfn: unknown op %d\n", op);
  }
}
