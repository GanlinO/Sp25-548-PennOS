/* ─── src/syscall/syscall_kernel.c ───────────────────────────────────────── */
#include "syscall_kernel.h"
#include "../internal/process_control.h"
#include "../internal/pennfat_kernel.h"
#include "../util/utils.h"
#include <errno.h>
#include <unistd.h>   // dup2, close
#include <stdlib.h>
#include <string.h>   /* ← for memset */


/* helper that converts (negative) kernel return → errno */
static int kret(int krc) { if (krc >= 0) return krc; errno = -krc; return -1; }

/* ---------- internal helper to pass (fd0,fd1) to the new routine -------- */

typedef struct spawn_wrapper_arg {
  void *(*func)(void *);
  void  *real_arg;
  int    fd0;
  int    fd1;
} spawn_wrapper_arg;

/* ------------------------------------------------------------------ */
/*  redirect_fd() – move an existing user-FD `src` onto `target`      */
/*  (stdin = 0, stdout = 1).  Works only inside the CHILD, i.e. after */
/*  s_spawn has given the child its own PCB.                          */
/* ------------------------------------------------------------------ */
static void redirect_fd(int target, int src)
{
    if (src < 0 || src == target) return;        /* nothing to do      */

    pcb_t *self = k_get_self_pcb();
    proc_fd_t *src_ent, *tgt_ent;

    /* make sure `src` exists */
    if (pcb_fd_get(self, src, &src_ent) == -1)    /* EBADF already set  */
        return;

    /* if target already occupied, close it first (will free its entry) */
    if (pcb_fd_get(self, target, &tgt_ent) == 0)
        pcb_fd_close(self, target);

    /* move the entry: */
    vec_set_force(&self->fds, target, src_ent);
    vec_set_force(&self->fds, src,   NULL);
}

void *spawn_entry_wrapper(void *raw)
{
    struct spawn_wrapper_arg *wrap = (struct spawn_wrapper_arg *)raw;

    /* ---------- fd inheritance plumbing ---------- */
    redirect_fd(STDIN_FILENO,  wrap->fd0);
    redirect_fd(STDOUT_FILENO, wrap->fd1);

    /* now run the user code ------------------------ */
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
int s_open(const char *path, int mode)
{
    if (!path || *path == '\0')
        return (errno = EINVAL, -1);

    /* delegate to kernel – it already enforces exclusive write/append */
    int kfd = k_open(path, mode);
    if (kfd < 0) return kret(kfd);

    /* allocate a per-process slot */
    proc_fd_t *entry = malloc(sizeof *entry);
    if (!entry) { k_close(kfd); return (errno = ENOMEM, -1); }

    *entry = (proc_fd_t){ .kfd = kfd,
                          .flags = mode,
                          .offset = 0,
                          .in_use = true };

    /* F_APPEND ⇒ position at EOF */
    if (mode & F_APPEND) {
        int off = k_lseek(kfd, 0, F_SEEK_END);
        if (off < 0) { free(entry); k_close(kfd); return kret(off); }
        entry->offset = off;
    }

    int ufd = pcb_fd_alloc(k_get_self_pcb(), (void *)entry);
    if (ufd == -1) {                    /* pcb helper sets errno → EMFILE */
        free(entry); k_close(kfd); return -1;
    }
    return ufd;
}

static inline int fd_lookup(int ufd, proc_fd_t **out)
{
  proc_fd_t *raw;
    if (pcb_fd_get(k_get_self_pcb(), ufd, &raw) == -1)  /* EBADF set */
        return -1;
    *out = raw;
    return 0;
}

/* ---------- s_read --------------------------------------------------- */
int s_read(int ufd, int n, char *buf)
{
    proc_fd_t *ent;
    if (fd_lookup(ufd, &ent) == -1) return -1;
    if (!(ent->flags & F_READ))        return (errno = EBADF, -1);

    int r = k_read(ent->kfd, n, buf);
    if (r >= 0) ent->offset += r;
    return kret(r);
}

/* ---------- s_write -------------------------------------------------- */
int s_write(int ufd, const char *buf, int n)
{
    proc_fd_t *ent;
    if (fd_lookup(ufd, &ent) == -1) return -1;
    if (!(ent->flags & (F_WRITE | F_APPEND)))
        return (errno = EBADF, -1);

    int w = k_write(ent->kfd, buf, n);
    if (w >= 0) ent->offset += w;
    return kret(w);
}


/* ---------- s_close -------------------------------------------------- */
int s_close(int ufd)
{
    proc_fd_t *ent;
    if (fd_lookup(ufd, &ent) == -1) return -1;

    int rc = k_close(ent->kfd);
    pcb_fd_close(k_get_self_pcb(), ufd);
    free(ent);
    return kret(rc);
}


/* ---------- s_lseek -------------------------------------------------- */
int s_lseek(int ufd, int off, int whence)
{
    proc_fd_t *ent;
    if (fd_lookup(ufd, &ent) == -1) return -1;

    int newoff = k_lseek(ent->kfd, off, whence);
    if (newoff < 0) return kret(newoff);
    ent->offset = newoff;
    return newoff;
}

PennFatErr s_touch(const char *p){ return k_touch(p); }

int s_unlink(const char *path)
{
    if (!path || *path == '\0')
        return (errno = EINVAL, -1);
    return kret(k_unlink(path));
}

PennFatErr s_chmod(const char *p,uint8_t perm){ return k_chmod(p,perm); }

int s_rename(const char *o,const char *n){
    PennFatErr r = k_rename(o,n);
    if(r!=PennFatErr_OK){ map_errno(r); return -1; }
    return 0;
}

/* ────────────────  s_ls  ───────────────────────────────────────── */
/*  List a single file or (if fname==NULL) every file in cwd.        */
/*  We merely translate the PennFAT error code to errno.             */
int s_ls(const char *fname)
{
    PennFatErr r = k_ls(fname);
    if (r != PennFatErr_OK) {
        switch (r) {
            case PennFatErr_NOTDIR: errno = ENOTDIR;  break;
            case PennFatErr_EXISTS: errno = ENOENT;   break;
            case PennFatErr_PERM:   errno = EACCES;   break;
            default:                errno = EIO;      break;
        }
        return -1;
    }
    return 0;                       /* success */
}

int s_getattr(const char *p, PennFatAttr *a)
{
    PennFatErr e = k_getattr(p, a);
    if (e != PennFatErr_OK) { map_errno(e); return -1; }
    return 0;
}

