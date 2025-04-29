#include "shell.h"
#include "../user/stress.h"
#include "../syscall/syscall_kernel.h"
#include "../common/pennos_signals.h"
#include "../util/parser.h"
#include "../util/utils.h"
#include "jobs.h"
#include <signal.h>
#include <unistd.h> 

#include "../internal/pennfat_kernel.h"
#include "../common/pennfat_definitions.h"
#include "../internal/process_control.h"

#include <stdlib.h>   // NULL, atoi
#include <errno.h>
#include <unistd.h>   // STDIN_FILENO / read
#include <string.h>
#include <ctype.h>    // isdigit (for sleep)

/* ---------- forward-declarations for built-ins used below ---------- */
void* jobs_builtin(void*);
void* bg(void*);
void* fg(void*);
void* logout_cmd(void*);

void* touch(void* arg);
void* ls(void* arg);
void* cat(void* arg);
void* chmod(void* arg);
void* cp(void* arg);      /* NEW */
void* mv(void* arg);      /* NEW */
void* rm(void* arg);      /* NEW */
void* kill_cmd(void* arg);     /* renamed to avoid clash          */


/*──────────────────────────────────────────────────────────────*/
/*  Dispatch tables                                             */
/*──────────────────────────────────────────────────────────────*/

typedef void* (*thd_func_t)(void*);

typedef struct cmd_func_match_t{
  const char* cmd;
  thd_func_t  func;
} cmd_func_match_t;

/* ───────────────────────────────────────────────
 *  built-ins that MUST run in a *separate* PennOS
 *  process (section 3.1 first table)
 * ───────────────────────────────────────────────*/
static cmd_func_match_t independent_funcs[] = {
  {"ps",        ps},
  {"echo",      echo},
  {"sleep",     u_sleep},      /* user types “sleep 10”          */
  {"touch",     touch},        /* NEW */
  {"ls",        ls},           /* NEW */
  {"cat",       cat},          /* NEW */
  {"chmod",     chmod},   
  {"zombify",   zombify},
  {"orphanify", orphanify},
  {"busy",      busy},
  {"kill",      kill_cmd},     /* renamed                        */
    {"cp",        cp},
  {"mv",        mv},
  {"rm",        rm},
  {"hang",   hang},
  {"nohang", nohang},
  {"recur",  recur},
  {"crash",  crash},
  {NULL, NULL}
};

/* ───────────────────────────────────────────────
 *  built-ins that run **inside the shell**
 *  (section 3.1 “sub-routine” table)
 * ───────────────────────────────────────────────*/
static cmd_func_match_t inline_funcs[] = {
    {"nice",      u_nice},
    {"nice_pid",  u_nice_pid},
    {"man",       man},
    {"jobs",      jobs_builtin},
    {"bg",        bg},
    {"fg",        fg},
    {"logout",    logout_cmd},
    {NULL, NULL}
  };

/*──────────────────────────────────────────────────────────────*/
/*          MAIN PROGRAM (existing content remains)             */
/*──────────────────────────────────────────────────────────────*/

#define INITIAL_BUF_LEN (4096)
#define PROMPT "$ "

static char* buf = NULL;
static int   buf_len = 0;
static bool  exit_shell = false;
static pid_t shell_pgid;                /* for signal-forwarding */
static pid_t fg_pid = 0;          /* == 0  → no foreground job right now  */

static struct parsed_command* read_command();
static pid_t process_one_command(char ***cmdv, size_t stages,
                                   const char *stdin_file,
                                   const char *stdout_file,
                                   const char *stderr_file,
                                   bool append_out);

static thd_func_t get_func_from_cmd(const char * cmd_name, cmd_func_match_t* table);
static int  get_argc(char** argv);
static bool str_to_int(const char * str, int* ret_val);

#ifdef DEBUG
static void debug_print_argv(char** argv);
static void debug_print_parsed_command(struct parsed_command*);
#endif



static pid_t spawn_stage(char **argv, int fd_in, int fd_out);
static int  open_redirect(int *fd, const char *path, int flags);

/*──────────────────────────────────────────────────────────────*/
/*                NEW  BUILT-IN  IMPLEMENTATIONS                */
/*──────────────────────────────────────────────────────────────*/

/*──────────────────────────────────────────────────────────────*/
/*    helper – guarantee we never close 0 / 1 / 2 by mistake    */
/*──────────────────────────────────────────────────────────────*/
/* If open() returns fd 0,1,2 we immediately dup the file by
 * opening it a 2nd time, then carry on with the duplicate ≥3
 * and leave the first handle untouched.  (Leaking one extra
 * descriptor in the child process is harmless – the kernel
 * reclaims it when the process exits.)                         */
static int ensure_nonstd_fd(const char *path, int mode, int fd)
{
    if (fd >= 3)          /* already safe */
        return fd;

    int d = s_open(path, mode);   /* 2nd open → guaranteed ≥3 */
    if (d < 0)
        return fd;        /* fall back – we'll just avoid close() */
    return d;
}

static bool pennfat_is_noent(PennFatErr e)
{                       /* “file does not exist” in this API   */
    return e == PennFatErr_EXISTS;
}

static bool pennfat_is_perm(PennFatErr e)
{   return e == PennFatErr_PERM; }


/* ---------- touch ---------- */
void* touch(void* arg)
{
  char** argv = (char**)arg;
  if (!argv || !argv[1]) {
    fprintf(stderr, "touch: missing operand\n");
    return NULL;
  }
  for (int i = 1; argv[i]; ++i) {
    PennFatErr err = s_touch(argv[i]);
    if (err) fprintf(stderr, "touch: %s: %s\n", argv[i],
                     PennFatErr_toErrString(err));
  }
  return NULL;
}

/* ---------- ls (no arguments, PennFAT root only) ---------- */
void* ls(void* arg)
{
    char **argv = (char**)arg;
  
    /* no operand → list cwd (NULL means “.” to PennFAT wrapper) */
    if (!argv || !argv[1]) {
        PennFatErr e = s_ls(NULL);
        if (e) fprintf(stderr, "ls: %s\n", PennFatErr_toErrString(e));
        return NULL;
  }
  
    /* one or more explicit paths */
    for (int i = 1; argv[i]; ++i) {
        PennFatErr e = s_ls(argv[i]);
        if (e) fprintf(stderr, "ls: %s: %s\n",
                       argv[i], PennFatErr_toErrString(e));
    }
  return NULL;
}

/* ---------- chmod (updated) ---------- */
static int parse_perm_abs(const char *s, uint8_t *mask)
/* Accept **absolute** permission strings:
 *   • one octal digit 0-7   (0 = ---, 7 = rwx)
 *   • any combination of rwx (e.g. "rw", "x", "rwx")
 * Returns 0 on success, –1 on error.                                  */
{
    if (!s || !*s) return -1;

    /* octal digit? -------------------------------------------------- */
    if (s[1] == '\0' && *s >= '0' && *s <= '7') {
        static const uint8_t lut[8] = {
            0,                     /* 0 --- */
            PERM_EXEC,             /* 1 --x */
            PERM_WRITE,            /* 2 -w- */
            PERM_WRITE|PERM_EXEC,  /* 3 -wx */
            PERM_READ,             /* 4 r-- */
            PERM_READ |PERM_EXEC,  /* 5 r-x */
            PERM_READ |PERM_WRITE, /* 6 rw- */
            PERM_READ |PERM_WRITE|PERM_EXEC  /* 7 rwx */
        };
        *mask = lut[*s - '0'];
        return 0;
    }

        /* symbolic “+rwx” / “-wx” form --------------------------------- */
    if (*s == '+' || *s == '-') {
          bool add = (*s == '+');
          ++s;
          uint8_t m = 0;
          for (; *s; ++s) {
              if      (*s == 'r') m |= PERM_READ;
              else if (*s == 'w') m |= PERM_WRITE;
              else if (*s == 'x') m |= PERM_EXEC;
              else                return -1;
          }
          *mask = add ? m : (uint8_t)(0x80 | m);   /* high bit ⇒ remove */
          return 1;                                /* special code */
      }
    /* symbolic “rwx” form ------------------------------------------ */
    uint8_t m = 0;
    for (; *s; ++s) {
        if      (*s == 'r') m |= PERM_READ;
        else if (*s == 'w') m |= PERM_WRITE;
        else if (*s == 'x') m |= PERM_EXEC;
        else                return -1;          /* invalid char */
    }
    if (m == 0) return -1;                      /* empty mask */
    *mask = m;
    return 0;
}

void* chmod(void *arg)
{
    char **argv = (char **)arg;
    if (!argv || !argv[1] || !argv[2]) {
        fprintf(stderr, "chmod: usage: chmod MODE FILE …\n");
        return NULL;
    }

    const char *mode   = argv[1];
    bool relative_form = (mode[0] == '+' || mode[0] == '-');

    for (int i = 2; argv[i]; ++i) {
        uint8_t new_perm;

        /* ------------------------------------------------ relative */
        if (relative_form) {
            PennFatAttr a;
            if (s_getattr(argv[i], &a) == -1) {   /* prints errno msg */
                perror("chmod");
                continue;
            }
            uint8_t cur = a.perm & 0x7;           /* keep rwx only    */
            bool add    = (mode[0] == '+');

            for (const char *p = mode + 1; *p; ++p) {
                uint8_t bit =
                      (*p == 'r') ? PERM_READ  :
                      (*p == 'w') ? PERM_WRITE :
                      (*p == 'x') ? PERM_EXEC  : 0;
                if (!bit) {                       /* bad flag        */
                    fprintf(stderr,
                            "chmod: invalid mode flag '%c'\n", *p);
                    goto nextfile;
                }
                cur = add ? (cur | bit) : (cur & ~bit);
            }
            new_perm = cur;
        }
        /* ------------------------------------------------ absolute */
        else {
            if (parse_perm_abs(mode, &new_perm) < 0) {
                fprintf(stderr, "chmod: invalid mode '%s'\n", mode);
                goto nextfile;
            }
        }

        /* finally apply ------------------------------------------- */
        {
            PennFatErr err = s_chmod(argv[i], new_perm);
            if (err != PennFatErr_OK)
                fprintf(stderr, "chmod: %s: %s\n",
                        argv[i], PennFatErr_toErrString(err));
        }

    nextfile: ;       /* label target – nothing else to do */
    }
    return NULL;
}

/* ---------- cat -------------------------------------------------- */
#define CAT_BUFSZ 4096
void *cat(void *arg)
{
    char **argv = (char **)arg;

    /* no file arguments → copy stdin → stdout */
    if (!argv || !argv[1]) {
        char buf[CAT_BUFSZ];
        int  n;
        while ((n = s_read(STDIN_FILENO, CAT_BUFSZ, buf)) > 0)
            s_write(STDOUT_FILENO, buf, n);
        return NULL;
    }

    /* one or more file names */
    for (int i = 1; argv[i]; ++i) {
        int fd0 = s_open(argv[i], K_O_RDONLY);
        if (fd0 < 0) {
            fprintf(stderr, "cat: %s: %s\n", argv[i], strerror(errno));
            continue;
        }
        int fd = ensure_nonstd_fd(argv[i], K_O_RDONLY, fd0);

        char buf[CAT_BUFSZ];
        int  n;
        while ((n = s_read(fd, sizeof buf, buf)) > 0)
            s_write(STDOUT_FILENO, buf, n);

        if (fd >= 3)          /* never close 0/1/2 */
            s_close(fd);
    }
    return NULL;
}


/*----------- echo -----------------------------------------------------------*/
void* echo(void *arg)
{
    char **argv = (char **)arg;
    if (!argv) return NULL;

    for (int i = 1; argv[i]; ++i) {
        const char *w = argv[i];
        s_write(STDOUT_FILENO, w, (int)strlen(w));
        if (argv[i + 1])
            s_write(STDOUT_FILENO, " ", 1);
    }
    s_write(STDOUT_FILENO, "\n", 1);
    return NULL;
}

/*----------- u_sleep   (shell command:  sleep N seconds) --------------------*/
void* u_sleep(void* arg)
{
  char** argv = (char**)arg;
  if (!argv || !argv[1]) {
    fprintf(stderr, "sleep: missing <seconds>\n");
    return NULL;
  }

  /* ensure numeric */
  for (const char* p = argv[1]; *p; ++p) {
    if (!isdigit((unsigned char)*p)) {
      fprintf(stderr, "sleep: '%s' is not a positive integer\n", argv[1]);
      return NULL;
    }
  }

  int secs = atoi(argv[1]);
  if (secs <= 0) return NULL;

  /* 1 clock-tick = 0.1 s (see CLOCK_TICK_IN_USEC in process_control.c) */
  clock_tick_t ticks = (clock_tick_t)(secs * 10);
  s_sleep(ticks);
  return NULL;
}

/*----------- man  (static help text) ----------------------------------------*/
static const char* help_text =
  "Built-in commands:\n"
  "  echo TEXT …            – print TEXT to stdout\n"
  "  sleep N                – suspend shell for N seconds\n"
  "  ps                     – list processes\n"
  "  kill [-stop|-cont] PID – send signal to PID\n"
  "  nice PRIORITY cmd …    – spawn cmd with priority\n"
  "  nice_pid PRIORITY PID  – change priority of existing PID\n"
  "  man                    – this help text\n";

void* man(void* arg)
{
  (void)arg;
  fputs(help_text, stdout);
  return NULL;
}

static void forward(int signo)
{
    if (fg_pid > 0) {
        s_kill(fg_pid,
               (signo == SIGINT) ? P_SIGTERM : P_SIGSTOP);
    }
     write(STDERR_FILENO, "\n", 1);      /* put prompt on next line */
 }

static void shell_install_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = forward;
    sigemptyset(&sa.sa_mask);
     /* read() in prompt loop */
    sa.sa_flags = SA_RESTART;

    sigaction(SIGINT,  &sa, NULL);     /* Ctrl-C  */
    sigaction(SIGTSTP, &sa, NULL);     /* Ctrl-Z  */
}

/*======================================================================*/
/*  Data-moving built-ins: cp / mv / rm                                 */
/*======================================================================*/

/* ---------- cp --------------------------------------------------- */
void *cp(void *arg)
{
    char **argv = (char **)arg;
    if (!argv || !argv[1] || !argv[2]) {
        fprintf(stderr, "cp: usage: cp SRC DST\n");
        return NULL;
    }
    const char *src = argv[1], *dst = argv[2];

    int sfd0 = s_open(src, K_O_RDONLY);
    if (sfd0 < 0) {
        fprintf(stderr, "cp: %s: %s\n", src, strerror(errno));
        return NULL;
    }
    int sfd = ensure_nonstd_fd(src, K_O_RDONLY, sfd0);

    int dfd0 = s_open(dst, K_O_CREATE | K_O_TRUNC | K_O_WRONLY);
    if (dfd0 < 0) {
        fprintf(stderr, "cp: %s: %s\n", dst, strerror(errno));
        if (sfd >= 3) s_close(sfd);
        return NULL;
    }
    int dfd = ensure_nonstd_fd(dst, K_O_CREATE | K_O_TRUNC | K_O_WRONLY, dfd0);

    char buf[4096];
    int  n;
    while ((n = s_read(sfd, sizeof buf, buf)) > 0) {
        if (s_write(dfd, buf, n) != n) {
            fprintf(stderr, "cp: write error: %s\n", strerror(errno));
            break;
        }
    }

    if (sfd >= 3) s_close(sfd);
    if (dfd >= 3) s_close(dfd);
    return NULL;
}

/* ---------- rm ---------------------------------------------------- *
 * Remove one or more files.  Each file is handled independently, so
 * an error with f1 does not prevent attempts on f2, f3, …            *
 * Behaviour:
 *   • “No such file”   if the path does not exist
 *   • “Permission denied” when the caller lacks write permission
 *   • All other PennFAT errors are reported verbatim.               */
void* rm(void *arg)
{
    char **argv = (char**)arg;
    if (!argv || !argv[1]) {
        fprintf(stderr, "rm: usage: rm FILE …\n");
        return NULL;
    }

    for (int i = 1; argv[i]; ++i) {
        PennFatErr err = s_unlink(argv[i]);
        if (err == PennFatErr_OK)                       /* success */
            continue;

        /* translate common errors for user friendliness */
        if (pennfat_is_noent(err))
            fprintf(stderr, "rm: %s: No such file\n", argv[i]);
        else if (pennfat_is_perm(err))
            fprintf(stderr, "rm: %s: Permission denied\n", argv[i]);
        else
            fprintf(stderr, "rm: %s: %s\n",
                    argv[i], PennFatErr_toErrString(err));
    }
    return NULL;
}

/* ---------- mv (updated) ---------- */
void* mv(void *arg)
{
    char **argv = (char**)arg;
    if (!argv || !argv[1] || !argv[2]) {
        fprintf(stderr, "mv: usage: mv SRC DST\n");
        return NULL;
    }
    const char *src = argv[1], *dst = argv[2];

    /* 1. Make sure SRC exists & is readable */
    int fd = s_open(src, K_O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT)
            fprintf(stderr, "mv: %s: No such file\n", src);
        else if (errno == EACCES)
            fprintf(stderr, "mv: %s: Permission denied (read)\n", src);
        else
            perror("mv");
        return NULL;
    }
    s_close(fd);

    /* 2. If DST already exists, verify write permission                */
    fd = s_open(dst, K_O_WRONLY);          /* no K_O_CREATE here       */
    if (fd >= 0) {
        s_close(fd);                       /* write-able, good         */
    } else if (errno == EACCES) {          /* exists but RO           */
        fprintf(stderr,
                "mv: %s: Permission denied (write overwrite)\n", dst);
        return NULL;
    }
    /* ENOENT here is fine – file does not exist → will be created */

    /* 3. Try the rename itself                                        */
    if (s_rename(src, dst) != 0) {
        if (errno == EACCES)
            fprintf(stderr,
                    "mv: cannot rename %s → %s: Permission denied\n",
                    src, dst);
        else
            perror("mv");
    }
    return NULL;
}


/*──────────────────────────────────────────────────────────────*/
/*      The remainder of shell.c is unchanged (↓ existing)      */
/*──────────────────────────────────────────────────────────────*/

void* shell_main(void* arg) {
  buf_len = INITIAL_BUF_LEN;
  buf = malloc(sizeof(char) * buf_len);
  assert_non_null(buf, "malloc buf");

  struct parsed_command* cmd = NULL;
  
  shell_pgid = s_getselfpid();
  assert_non_negative(shell_pgid, "Shell PID invalid");
  jobs_init();
  shell_install_handlers();                                     /* step 6 */

  while (!exit_shell) {
            int st;
        pid_t kid;
        while ((kid = s_waitpid(-1, &st, true)) > 0) {
            if (P_WIFSTOPPED(st))
                jobs_update(kid, JOB_STOPPED);
            else if (P_WIFSIGNALED(st) || P_WIFEXITED(st))
                jobs_update(kid, JOB_DONE);
            else if (st == P_SIGCONT)
                jobs_update(kid, JOB_RUNNING);
        }

    free(cmd);

    fprintf(stderr, PROMPT);
    cmd = read_command();
    if (!cmd || cmd->num_commands == 0) continue;

       /* ─────────────────────────────────────────────────────────────
    *  STEP ➊ : built-ins that must run *inside* the shell (nice,
     *           bg, fg, jobs, logout, man, …).
     *           If the first word of the command matches one of
     *           those, execute it synchronously and go back to the
     *           prompt – no pipes, no redirections, no child proc.     * ────────────────────────────────────────────────────────────*/
    {
          char **argv0 = cmd->commands[0];        /* words of 1st stage */
          thd_func_t inl = get_func_from_cmd(argv0[0], inline_funcs);
          if (inl) {               /* found a shell-local built-in */
              inl(argv0);          /* run it right here            */
              continue;            /* prompt user again            */
          }
      }
  
      /* ────────────────────────────────────────────────────────────
       *  From here on we know the command is *not* shell-local, so
       *  we treat it like an external pipeline: handle < > >> and
       *  possibly create one or many child processes.
       * ────────────────────────────────────────────────────────────*/

 pid_t child_pid = process_one_command(cmd->commands,
                                        cmd->num_commands,
                                         cmd->stdin_file,
                                         cmd->stdout_file,
                                         /* stderr */ NULL,
                                         cmd->is_file_append);

    if (child_pid <= 0) continue;

    if (!cmd->is_background) {            /* foreground job           */
      fg_pid = child_pid;                 /* record for signal fwd    */
      s_tcsetpid(child_pid);
      s_waitpid(child_pid, NULL, false);
      s_tcsetpid(shell_pgid);
      fg_pid = 0;                         /* no FG job any more       */
    } else {
              /* 1. register in job table */
              int jid = jobs_add(child_pid, buf, true);

              /* 2. print the “[jid] pid” line */
              fprintf(stderr, "[%d] %d\n", jid, (int)child_pid);

    }

    
  }

  if (cmd) free(cmd);        /* guard against the last continue */

  free(buf);

  jobs_shutdown(); 


  fprintf(stderr, "Shell exits\n");
  /* let the wrapper do the bookkeeping (k_exit) */             
  return NULL;
}




/* Existing built-ins (busy / kill / ps / testing helpers) remain unchanged */
/* … (the rest of the original file’s content is intentionally left intact) */


/******************************************
 *     INDEPENDENT BUILT-INS              *
 ******************************************/

void* ps(void* arg) {
  s_printprocess();
  return NULL;
}

void* busy(void* arg) {
  while (true) {
    // intentionally spinning
  }
  return NULL;
}

void* kill_cmd(void* arg) {            /* ➋ renamed implementation   */
  // TODO: not completely finished

  if (!arg) {
    return NULL;
  }

  char** argv = (char**) arg;

  // VALIDATE ARGUMENTS
  if (!argv || argv[0] == NULL) {
    fprintf(stderr, "Error: Invalid arg.\n");
    return NULL;
  }

  int argc = get_argc(argv);
  // need at least 2 arguments
  if (argc < 2) {
    fprintf(stderr, "%s Error: Incorrect number of args.\n", argv[0]);
    return NULL;
  }

  int pid_start_index = 1;
  int signal = P_SIGTERM;
  if (argv[1] && argv[1][0] == '-') {
    ++pid_start_index;

    if (strcmp(argv[1], "-cont") == 0) {
      signal = P_SIGCONT;
    } else if (strcmp(argv[1], "-stop") == 0) {
      signal = P_SIGSTOP;
    } else if (strcmp(argv[1], "-term") == 0) {
      signal = P_SIGTERM;
    } else {
      fprintf(stderr, "%s Error: Invalid arg: %s.\n", argv[0], argv[1]);
      return NULL;
    }
  }

  // TODO: error checking and multiple processes

  int pid;
  if (!str_to_int(argv[pid_start_index], &pid) || pid <= 0) {
    fprintf(stderr, "%s Error: Invalid arg: %s. PID number should be a positive integer.\n", argv[0], argv[pid_start_index]);
    return NULL;
  }

  if (s_kill(pid, signal) == 0) {
       switch (signal) {
              case P_SIGSTOP: jobs_update(pid, JOB_STOPPED);           break;
              case P_SIGCONT: jobs_update(pid, JOB_RUNNING);           break;
              case P_SIGTERM: jobs_update(pid, JOB_DONE);              break;
          }
  } else {
    // TODO: errno checking, more verbose error explanation
    fprintf(stderr, "Error sending signal to PID [%d].\n", pid);
  }

  return NULL;
}

 // TODO: add other command functions

 /******************************************
 *            SUB-ROUTINES                *
 ******************************************/

 // TODO: add other command functions

void* u_nice_pid(void* arg) {
  
  char** argv = (char**) arg;

  // VALIDATE ARGUMENTS
  if (!argv || argv[0] == NULL) {
    fprintf(stderr, "Error: Invalid arg.\n");
    return NULL;
  }

  int argc = get_argc(argv);
  // need exactly 3 arguments
  if (argc != 3) {
    fprintf(stderr, "%s Error: Incorrect number of args.\n", argv[0]);
    return NULL;
  }

  int priority, pid;
  if (!str_to_int(argv[2], &pid) || pid <= 0) {
    fprintf(stderr, "%s Error: Invalid args. PID number should be a positive integer.\n", argv[0]);
    return NULL;
  }

  if (!str_to_int(argv[1], &priority) || priority < 0 || priority >= 3) {
    fprintf(stderr, "%s Error: Invalid args. Priority should be an integer between 0 and 2.\n", argv[0]);
    return NULL;
  }

  // SYSTEM CALL TO UPDATE NICE VALUE
  if (s_nice(pid, priority) == 0) {
    fprintf(stderr, "Successfully set PID[%d] to priority %d.\n", pid, priority);
  } else {
    // TODO: more verbose response with errno checking
    fprintf(stderr, "%s failed\n", argv[0]);
  }

  return NULL;
}


void* u_nice(void* arg) {
  char** argv = (char**) arg;
  if (!argv || argv[0] == NULL) {
    fprintf(stderr, "Error: Invalid arg.\n");
    return NULL;
  }

  // VALIDATE ARGUMENTS
  int argc = get_argc(argv);
  // need at least 3 arguments
  if (argc < 3) {
    fprintf(stderr, "%s Error: Incorrect number of args.\n", argv[0]);
    return NULL;
  }

  int priority;
  if (!str_to_int(argv[1], &priority) || priority < 0 || priority >= 3) {
    fprintf(stderr, "%s Error: Invalid args. Priority should be an integer between 0 and 2.\n", argv[0]);
    return NULL;
  }

  pid_t child_pid = 0;
  
  thd_func_t func = get_func_from_cmd(argv[2], independent_funcs);
  if (func != NULL) {
    // FOUND INDEPENDENT FUNC COMMAND
    // spawn new process to run the command
    child_pid = s_spawn(func, argv + 2, 0, 1);
    if (child_pid < 0) {
      // spawn failed somehow
      // fprintf(stderr, "%s Failed to spawn process for command: %s\n", argv[0], argv[2]);
    
    } else if (s_nice(child_pid, priority) == 0) {      // SYSTEM CALL TO UPDATE NICE VALUE
      // update nice value successful
      // fprintf(stderr, "Command run as PID[%d] and set to priority %d: %s\n", child_pid, priority, argv[2]);
    } else {
      // TODO: more verbose response with errno checking
      // fprintf(stderr, "Command run as PID[%d] but set priority failed: %s\n", child_pid, argv[2]);
    }

  } else {
    fprintf(stderr, "Invalid command: %s\n", argv[2]);
    return NULL;
  }

  // RETURN PID
  pid_t* ret = malloc(sizeof(pid_t));
  *ret = child_pid;
  return ret;

}

/******************************************
 *            TEST HELPERS                *
 ******************************************/

void* zombie_child(void* arg) {
  // do nothing and exit right away intentionally
  return NULL;
}

void* zombify(void* arg) {
  char* args[] = {"zombie_child", NULL};
  s_spawn(zombie_child, args, 0, 1);
  while (1);
  return NULL;
}

void* orphan_child(void* arg) {
  // spinning intentionally
  while (1);
  return NULL;
}

void* orphan_child_autodie(void* arg) {
  s_sleep(20);
  return NULL;
}

void* orphanify(void* arg) {
  char* args[] = {"orphan_child", NULL};
  s_spawn(orphan_child, args, 0, 1);
  char* args2[] = {"orphan_child_autodie", NULL};
  s_spawn(orphan_child_autodie, args2, 0, 1);
  return NULL;
}

/* open <file> for shell redirection, return FD or negative error */
/* — already defined once above — */


/******************************************
 *       internal help functions          *
 ******************************************/

static struct parsed_command* read_command() {
  /* … unchanged … */
  /* (full body remains exactly as in your previous version) */
  /* ------------------------------------------------------- */
  // read user input
  ssize_t bytes_read;


    // fprintf(stderr, "\033[1m");
    errno = 0;                                       /* keep EINTR       */
    bytes_read = read(STDIN_FILENO, buf, buf_len - 1);
    // fprintf(stderr, "\033[0m");

  if (bytes_read >= 0) {
    buf[bytes_read] = '\0';
  }

  /* reaching EOF (and just CTRL-D in terminal) */
  if (bytes_read == 0) {
    fprintf(stderr, "\n");
    exit_shell = true;
    return NULL;    // success
  }

  /* having error */
  if (bytes_read < 0) {
    /* interrupted by signal */
    if (errno == EINTR) {
      return NULL;
    }
    perror("shell_loop: error read input");
    exit_shell = true;
    return NULL;    // failure
  }

  /* empty line */
  if (bytes_read == 1 && buf[bytes_read - 1] == '\n') {
    return NULL;
  }

  /* parse command */
  struct parsed_command* pcmd_ptr = NULL;
  int parse_ret = parse_command(buf, &pcmd_ptr);
  if (parse_ret != 0) {
    /* invalid command */
    print_parser_errcode(stderr, parse_ret);
    fprintf(stderr, "ERR: invalid user command\n");
    free(pcmd_ptr);
    return NULL;
  }

  if (pcmd_ptr->num_commands == 0) {
    free(pcmd_ptr);
    return NULL;
  }

  return pcmd_ptr;
}

void* jobs_builtin(void* _arg)          /* jobs : list every job        */
{
    (void)_arg;
    jobs_list();
    return NULL;
}

/* bg [ %jid ]  – resume most-recent stopped job in background  */
void* bg(void* arg)
{
    char **argv = (char**)arg;
    job_t *j = NULL;

    if (argv[1]) {                                   /* explicit %N     */
        int jid = (argv[1][0] == '%') ? atoi(argv[1]+1) : atoi(argv[1]);
        j = jobs_by_jid(jid);
    } else {                                         /* pick latest S   */
        j = jobs_most_recent(1 << JOB_STOPPED);
    }

    if (!j) { fprintf(stderr, "bg: job not found\n"); return NULL; }
    if (j->state == JOB_RUNNING) {
        fprintf(stderr, "bg: job already running\n");
        return NULL;
    }

    s_kill(j->pid, P_SIGCONT);
    jobs_update(j->pid, JOB_RUNNING);
    fprintf(stderr, "[%d] %s &\n", j->jid, j->cmdline);
    return NULL;
}


/* fg [ %jid ]  – put job in foreground (stopped *or* background)       */
void* fg(void* arg)
{
    extern pid_t fg_pid;             /* declared earlier in shell.c      */
    char **argv = (char**)arg;
    job_t *j = NULL;

    if (argv[1]) {
        int jid = (argv[1][0] == '%') ? atoi(argv[1]+1) : atoi(argv[1]);
        j = jobs_by_jid(jid);
    } else {
        j = jobs_most_recent((1 << JOB_STOPPED) | (1 << JOB_RUNNING));
    }

    if (!j) { fprintf(stderr, "fg: job not found\n"); return NULL; }

    s_kill(j->pid, P_SIGCONT);                   /* make sure it runs   */
    jobs_update(j->pid, JOB_RUNNING);

    fg_pid = j->pid;                             /* for signal forward  */
    s_tcsetpid(j->pid);                          /* terminal to job     */

    /* block-wait until it stops again or terminates */
    int status;
    while (true) {
        s_waitpid(j->pid, &status, false);       /* blocking wait       */
                if (P_WIFSTOPPED(status)) {
                      jobs_update(j->pid, JOB_STOPPED);
                      fprintf(stderr,"[%d] Stopped  %s\n", j->jid, j->cmdline);
                      break;
                  }
                  if (P_WIFEXITED(status) || P_WIFSIGNALED(status)) {
                      fprintf(stderr,"[%d] Done     %s\n", j->jid, j->cmdline);
                      jobs_remove(j->pid);
                      break;
                  }
    }

    s_tcsetpid(shell_pgid);                      /* shell regains tty   */
    fg_pid = 0;
    return NULL;
}

void* logout_cmd(void* arg)
{
  if (jobs_have_stopped()) {
    fprintf(stderr, "logout: there are stopped jobs\n");
    return NULL;
  }
  exit_shell = true;
  return NULL;
}

/*------------------------------------------------------------------*/
/*  piping helpers / process_one_command – unchanged                */
/*------------------------------------------------------------------*/

static int open_redirect(int *fd, const char *path, int flags)
{
    int newfd = s_open(path, flags);
    if (newfd < 0) {
        fprintf(stderr, "shell: cannot open %s\n", path);
        return -1;
    }
    *fd = newfd;
    return 0;
}

static pid_t spawn_stage(char **argv, int fd_in, int fd_out)
{
    if (!argv || !argv[0]) return -1;

    thd_func_t func = get_func_from_cmd(argv[0], independent_funcs);
    if (!func) {
        fprintf(stderr, "command not found: %s\n", argv[0]);
        return -1;
    }
    return s_spawn(func, argv, fd_in, fd_out);
}

static pid_t process_one_command(char **cmdv[], size_t stages,
                                   const char *stdin_file,
                                   const char *stdout_file,
                                   const char *stderr_file,
                                   bool append_out)
{
  /* … body unchanged … */
  int prev_rd = STDIN_FILENO;
  int first_pid = -1;

  /* optional <  redirection for very first stage */
  if (stdin_file && open_redirect(&prev_rd, stdin_file, K_O_RDONLY) < 0)
      return -1;

  for (size_t s = 0; s < stages; ++s) {
      int pipefds[2] = {-1, -1};
      int this_out = STDOUT_FILENO;

      /* if NOT last stage, create a pipe */
      if (s + 1 < stages) {
          if (s_pipe(pipefds) < 0) {
              perror("pipe");
              return -1;
          }
          this_out = pipefds[1];            /* writer for this stage        */
      } else {
          /* last stage may have > or >>   */
          if (stdout_file) {
              int flags = K_O_CREATE | (append_out ? K_O_APPEND : K_O_WRONLY);
              if (open_redirect(&this_out, stdout_file, flags) < 0)
                  return -1;
          }
      }

      /* stderr redirection only applies to *last* stage (bash semantics) */
      if (s + 1 == stages && stderr_file) {
          int fd;
          if (open_redirect(&fd, stderr_file,
                            K_O_CREATE | K_O_WRONLY) < 0)
              return -1;
          /* (child duplicates fd on FD 2 inside spawn)                   */
      }

      pid_t pid = spawn_stage(cmdv[s], prev_rd, this_out);
      if (pid < 0) return -1;
      if (first_pid == -1) first_pid = pid;

      /* parent closes ends it no longer needs */
      if (prev_rd != STDIN_FILENO) s_close(prev_rd);
      if (this_out != STDOUT_FILENO) s_close(this_out);

      prev_rd = pipefds[0];  /* read end for next iteration (or dangling) */
  }
  return first_pid;
}

static thd_func_t get_func_from_cmd(const char * cmd_name, cmd_func_match_t* func_match) {
  for (size_t i = 0; func_match[i].cmd != NULL; ++i) {
    if (strcmp(func_match[i].cmd, cmd_name) == 0) {
      return func_match[i].func;
    }
  }
  return NULL;
}

static int get_argc(char** argv) {
  int i = 0;
  while (argv[i] != NULL) {
    ++i;
  }
  return i;
}

/**
 * Helper function to convert string to int, and return whether the conversion is successful
 */
static bool str_to_int(const char * str, int* ret_val) {
  if (!str) {
    return false;
  }

  char* end;
  int res = strtol(str, &end, 10);

  if (*end != '\0') {
    return false;
  }

  if (ret_val) {
    *ret_val = res;
  }

  return true;
}

#ifdef DEBUG
static void debug_print_argv(char** argv) {
  if (!argv) {
    return;
  }

  for (size_t i = 0; argv[i] != NULL; ++i) {
    fprintf(stderr, "argv[%zu]: %s\n", i, argv[i]);
  }
}

static void debug_print_parsed_command(struct parsed_command* cmd) {
  if (!cmd) {
    return;
  }

  size_t command_num = cmd->num_commands;

  for (size_t c = 0; c < command_num; ++c) {
    fprintf(stderr, "command %zu:\n", c);
    debug_print_argv(cmd->commands[c]);
  }
}
#endif /* DEBUG */
