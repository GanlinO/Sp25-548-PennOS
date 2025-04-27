/* ─── src/syscall/syscall_kernel.c ───────────────────────────────────────── */
#include "syscall_kernel.h"
#include "../internal/process_control.h"
#include "../util/utils.h"
#include <errno.h>
#include <unistd.h>   // dup2, close
#include <stdlib.h>

/* ---------- internal helper to pass (fd0,fd1) to the new routine -------- */

typedef struct spawn_wrapper_arg {
  void *(*func)(void *);
  void  *real_arg;
  int    fd0;
  int    fd1;
} spawn_wrapper_arg;

/* runs in the CHILD ─ before user “func” */
static void *spawn_entry_wrapper(void *raw)
{
  spawn_wrapper_arg *wrap = (spawn_wrapper_arg *)raw;

  /* ---------- fd inheritance plumbing ---------- */
  if (wrap->fd0 >= 0 && wrap->fd0 != STDIN_FILENO) {
    dup2(wrap->fd0, STDIN_FILENO);
    close(wrap->fd0);
  }
  if (wrap->fd1 >= 0 && wrap->fd1 != STDOUT_FILENO) {
    dup2(wrap->fd1, STDOUT_FILENO);
    close(wrap->fd1);
  }

  /* hand-off to the user function */
  void *ret = wrap->func(wrap->real_arg);

  free(wrap);
  return ret;
}

/* -------------------------- s_spawn -------------------------------------- */
pid_t s_spawn(void* (*func)(void*), char* argv[], int fd0, int fd1)
{
  if (!func) { errno = EINVAL; return -1; }

  /* 1. create PCB */
  pcb_t *parent = k_get_self_pcb();
  assert_non_null(parent, "s_spawn: parent missing");

  pcb_t *child  = k_proc_create(parent);
  if (!child) { errno = EAGAIN; return -1; }

  /* 2. wrap arguments for the child */
  spawn_wrapper_arg *wrap = malloc(sizeof(*wrap));
  if (!wrap) { k_proc_cleanup(child); errno = ENOMEM; return -1; }

  *wrap = (spawn_wrapper_arg){
      .func     = func,
      .real_arg = argv,
      .fd0      = fd0,
      .fd1      = fd1,
  };

  /* 3. start routine (initially suspended; scheduler will run it) */
  if (k_set_routine_and_run(child, spawn_entry_wrapper, wrap) < 0) {
      free(wrap);
      k_proc_cleanup(child);
      errno = EAGAIN;
      return -1;
  }

  return k_get_pid(child);     /* success: return new PID */
}

/* ------------------- thin wrappers -------------------------------------- */
pid_t s_waitpid(pid_t pid, int *wstatus, bool nohang)
{
  pid_t r = k_waitpid(pid, wstatus, nohang);
  if (r < 0) errno = ECHILD;
  return r;
}

int s_kill(pid_t pid, int signal)
{
  int r = k_kill(pid, signal);
  if (r < 0) errno = ESRCH;
  return r;
}

int s_tcsetpid(pid_t pid)
{
  int r = k_tcsetpid(pid);
  if (r < 0) errno = EPERM;
  return r;
}

pid_t s_getselfpid() {
  pid_t self = k_get_pid(k_get_self_pcb());

  if (self <= 0) {
    // TODO: errno
    return -1;
  }

  return self;
}

void s_printprocess(void) {
  k_printprocess();
}

void s_exit(void) {
  k_exit();
}


int s_nice(pid_t pid, int priority) {
  if (priority >= 3) {  // PRIORITY_COUNT
    // TODO: set errno
    return -1;
  }

  return k_nice(pid, priority);
}

void s_sleep(clock_tick_t ticks) {
  k_sleep(ticks);
}
