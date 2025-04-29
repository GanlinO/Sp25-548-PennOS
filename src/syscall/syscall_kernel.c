/* ─── src/syscall/syscall_kernel.c ───────────────────────────────────────── */
#include "syscall_kernel.h"
#include "../internal/process_control.h"
#include "../internal/pennfat_kernel.h"
#include "../util/utils.h"
#include <errno.h>
#include <unistd.h>   // dup2, close
#include <stdlib.h>


/* helper: translate PennFAT errors → errno */
static int xlate_err(int e)
{
    switch (e) {
        case PennFatErr_PERM:  return EACCES;
        case PennFatErr_NOSPACE:return ENOSPC;
        case PennFatErr_EXISTS:return ENOENT;
        default:               return EIO;
    }
}

/* ---------- internal helper to pass (fd0,fd1) to the new routine -------- */

typedef struct spawn_wrapper_arg {
  void *(*func)(void *);
  void  *real_arg;
  int    fd0;
  int    fd1;
} spawn_wrapper_arg;

/* runs in the CHILD ─ before user “func” */
void *spawn_entry_wrapper(void *raw)
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


int s_pipe(int fds[2])
{
    int r = k_pipe(fds);
    if (r < 0) errno = EMFILE;   /* may fine-tune later */
    return r;
}

/* ───────────────── PennFAT helpers ────────────────────────────────── */
static void map_errno(PennFatErr e)
{
    switch (e) {
        case PennFatErr_PERM:      errno = EACCES;   break;
        case PennFatErr_NOTDIR:    errno = ENOTDIR;  break;
        case PennFatErr_EXISTS:    errno = ENOENT;   break;
        case PennFatErr_NOSPACE:   errno = ENOSPC;   break;
        default:                   errno = EIO;      break;
    }
}

/* thin 1-to-1 shims -------------------------------------------------- */
/* ---------- s_open -------------------------------------------- */
int s_open(const char *name, int mode)
{
    int kfd = k_open(name, mode);
    if (kfd < 0) { errno = xlate_err(kfd); return -1; }

    proc_fd_entry_t *ent = malloc(sizeof *ent);
    if (!ent) { k_close(kfd); errno = ENOMEM; return -1; }
    ent->kfd = kfd;

    pcb_t *self = k_get_self_pcb();
    int ufd = pcb_fd_alloc(self, ent);   /*  ←—— one call, all checks done */
    if (ufd == -1) { k_close(kfd); free(ent); return -1; }

    return ufd;
}

/* ---------- s_read --------------------------------------------------- */
int s_read(int fd, int n, char *buf)
{
    pcb_t *self = k_get_self_pcb();
    proc_fd_entry_t *ent;
    if (pcb_fd_get(self, fd, &ent) == -1)      /* sets errno → EBADF   */
        return -1;

    int rc = k_read(ent->kfd, n, buf);         /* PennFAT call         */
    if (rc < 0) { errno = xlate_err(rc); return -1; }
    return rc;                                 /* bytes read           */
}

/* ---------- s_write -------------------------------------------------- */
int s_write(int fd, const char *buf, int n)
{
    pcb_t *self = k_get_self_pcb();
    proc_fd_entry_t *ent;
    if (pcb_fd_get(self, fd, &ent) == -1)       /* EBADF               */
        return -1;

    int rc = k_write(ent->kfd, buf, n);
    if (rc < 0) { errno = xlate_err(rc); return -1; }
    return rc;
}


/* ---------- s_close -------------------------------------------------- */
int s_close(int fd)
{
    pcb_t *self = k_get_self_pcb();
    proc_fd_entry_t *ent;
    if (pcb_fd_get(self, fd, &ent) == -1)
        return -1;                              /* EBADF already set   */

    int rc = k_close(ent->kfd);
    free(ent);
    pcb_fd_close(self, fd);                      /* helper ← sets slot NULL */

    if (rc < 0) { errno = xlate_err(rc); return -1; }
    return 0;
}

/* ---------- s_lseek -------------------------------------------------- */
int s_lseek(int fd, int off, int whence)
{
    pcb_t *self = k_get_self_pcb();
    proc_fd_entry_t *ent;
    if (pcb_fd_get(self, fd, &ent) == -1)
        return -1;

    int rc = k_lseek(ent->kfd, off, whence);
    if (rc < 0) { errno = xlate_err(rc); return -1; }
    return rc;                                  /* new offset          */
}

PennFatErr s_touch(const char *p){ return k_touch(p); }
PennFatErr s_ls   (const char *p){ return k_ls   (p); }
PennFatErr s_chmod(const char *p,uint8_t perm){ return k_chmod(p,perm); }

int s_rename(const char *o,const char *n){
    PennFatErr r = k_rename(o,n);
    if(r!=PennFatErr_OK){ map_errno(r); return -1; }
    return 0;
}

int s_unlink(const char *p)
{
    int r = k_unlink(p);
    if (r != PennFatErr_OK) { errno = xlate_err(r); return -1; }
    return 0;
}


