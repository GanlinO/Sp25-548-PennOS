#include "shell.h"
#include "../syscall/syscall_kernel.h"
#include "../common/pennos_signals.h"
#include "../util/parser.h"
#include "../util/utils.h"
#include "jobs.h"
#include <signal.h>

#include "../internal/pennfat_kernel.h"
#include "../common/pennfat_definitions.h"

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

static int open_for_read (const char *path)               { return s_open(path, K_O_RDONLY); }
static int open_for_write(const char *path, bool append)  {
  int flags = K_O_CREATE | (append ? K_O_APPEND : K_O_WRONLY);
  return s_open(path, flags);
}

static pid_t spawn_stage(char **argv, int fd_in, int fd_out);
static int  open_redirect(int *fd, const char *path, int flags);

/*──────────────────────────────────────────────────────────────*/
/*                NEW  BUILT-IN  IMPLEMENTATIONS                */
/*──────────────────────────────────────────────────────────────*/

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
  (void)arg;          /* unused */
  PennFatErr err = s_ls(NULL);
  if (err) fprintf(stderr, "ls: %s\n", PennFatErr_toErrString(err));
  return NULL;
}

/* ---------- chmod ---------- */
/**
 * Translate a symbolic permission string to a bit-mask.
 * Accepts:  "rwx", "+rw", "-x", etc.  The leading ‘+’/‘-’ is ignored – we
 * presently treat the request as an *absolute* mask because the underlying
 * s_chmod() overwrites the whole permission set.
 * Returns 0xFF on syntax error.
 */
static uint8_t parse_perm_string(const char *s)
{
    if (!s) return 0xFF;
    if (*s == '+' || *s == '-')            /* optional sign */ ++s;

    uint8_t m = 0;
    for (; *s; ++s) {
        if      (*s == 'r') m |= PERM_READ;
        else if (*s == 'w') m |= PERM_WRITE;
        else if (*s == 'x') m |= PERM_EXEC;
        else                return 0xFF;   /* illegal character */
    }
    return (m == 0) ? 0xFF : m;
}

void* chmod(void* arg)
{
  char** argv = (char**)arg;
  if (!argv || !argv[1] || !argv[2]) {
      fprintf(stderr, "chmod: usage: chmod PERMS FILE …\n");
      return NULL;
  }

  /* parse the +rwx / -wx … string **once** */
  uint8_t perm = parse_perm_string(argv[1]);
  if (perm == 0xFF) {
      fprintf(stderr, "chmod: invalid permission string '%s'\n", argv[1]);
      return NULL;
  }

  /* try to apply it to every remaining operand */
  for (int i = 2; argv[i]; ++i) {
      PennFatErr err = s_chmod(argv[i], perm);
      if (err)
          fprintf(stderr, "chmod: %s: %s\n",
                  argv[i], PennFatErr_toErrString(err));
  }
  return NULL;
}

/* ---------- cat (read files from PennFAT, print to stdout) ---------- */
#define CAT_BUFSZ 4096
void* cat(void* arg)
{
    char** argv = (char**)arg;
  /* No file names → echo STDIN until EOF --------------------------- */
  if (!argv || !argv[1]) {
      char buf[CAT_BUFSZ];
      while (1) {
          PennFatErr n = s_read(STDIN_FILENO, CAT_BUFSZ, buf);
          if (n <= 0) break;
          fwrite(buf, 1, n, stdout);
      }
      return NULL;
  }
  char buf[CAT_BUFSZ];

  for (int i = 1; argv[i]; ++i) {
    int fd = s_open(argv[i], K_O_RDONLY);
    if (fd < 0) {
      fprintf(stderr, "cat: %s: %s\n", argv[i],
              PennFatErr_toErrString(fd));
      continue;
    }
    while (1) {
      PennFatErr r = s_read(fd, CAT_BUFSZ, buf);
      if (r < 0) { fprintf(stderr, "cat: read error\n"); break; }
      if (r == 0) break;
      fwrite(buf, 1, r, stdout);
    }
    s_close(fd);
  }
  return NULL;
}

/*----------- echo -----------------------------------------------------------*/
void* echo(void* arg)
{
  char** argv = (char**)arg;          /* argv[0] == "echo"              */
  if (!argv) return NULL;

  for (int i = 1; argv[i]; ++i) {
    fputs(argv[i], stdout);
    if (argv[i + 1]) fputc(' ', stdout);
  }
  fputc('\n', stdout);
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

// static void forward(int signo)
// {
//     job_t *fg = jobs_current_fg();
//     if (fg)
//         s_kill(fg->pid, (signo == SIGINT) ? P_SIGTERM : P_SIGSTOP);  /* fixed */
// }

/*======================================================================*/
/*  Data-moving built-ins: cp / mv / rm                                 */
/*======================================================================*/

/* cp  SRC DST  — copy a file inside PennFAT (no host –h support yet) */
void* cp(void* arg)
{
  char** argv = (char**)arg;
  if (!argv || !argv[1] || !argv[2]) {
    fprintf(stderr, "cp: usage: cp SRC DST\n");
    return NULL;
  }

  const char* src = argv[1];
  const char* dst = argv[2];

  int src_fd = s_open(src, K_O_RDONLY);
  if (src_fd < 0) {
    fprintf(stderr, "cp: cannot open %s\n", src);
    return NULL;
  }
  int dst_fd = s_open(dst, K_O_CREATE | K_O_WRONLY);
  if (dst_fd < 0) {
    fprintf(stderr, "cp: cannot create %s\n", dst);
    s_close(src_fd);
    return NULL;
  }

  char buf[4096];
  while (1) {
    PennFatErr n = s_read(src_fd, sizeof buf, buf);
    if (n < 0) { fprintf(stderr, "cp: read error\n"); break; }
    if (n == 0) break;                 /* EOF */
    if (s_write(dst_fd, buf, n) != n) {
      fprintf(stderr, "cp: write error\n");
      break;
    }
  }

  s_close(src_fd);
  s_close(dst_fd);
  return NULL;
}

/* mv  SRC DST  — rename inside PennFAT */
void* mv(void* arg)
{
  char** argv = (char**)arg;
  if (!argv || !argv[1] || !argv[2]) {
    fprintf(stderr, "mv: usage: mv SRC DST\n");
    return NULL;
  }

  if (s_rename(argv[1], argv[2]) != 0)
    fprintf(stderr, "mv: cannot rename %s -> %s\n", argv[1], argv[2]);
  return NULL;
}

/* rm  FILE…  — delete one or more files */
void* rm(void* arg)
{
  char** argv = (char**)arg;
  if (!argv || !argv[1]) {
    fprintf(stderr, "rm: usage: rm FILE...\n");
    return NULL;
  }

  for (int i = 1; argv[i]; ++i) {
    if (s_unlink(argv[i]) != 0)
      fprintf(stderr, "rm: cannot remove %s\n", argv[i]);
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
  jobs_init();                                   /* step 6 */

  while (!exit_shell) {
        /* ── 1. reap all dead children synchronously (NOHANG) ─────────── */
    while (s_waitpid(-1, NULL, true) > 0)   /* discard status */
        ;

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

  /*----------------------------------------------*
 *  Handle <  >  >>  from the parsed structure  *
 *----------------------------------------------*/
int redir_in  = STDIN_FILENO;   /* default: inherit from shell */
int redir_out = STDOUT_FILENO;
bool close_in  = false;         /* whether we must k_close later */
bool close_out = false;

/* open input redirection, if any */
if (cmd->stdin_file) {
  int fd = open_for_read(cmd->stdin_file);
  if (fd < 0) {
    fprintf(stderr, "shell: cannot open %s for reading\n", cmd->stdin_file);
    goto AFTER_LOOP_CLEANUP;
  }
  redir_in = fd;  close_in = true;
}

/* open output redirection, if any */
if (cmd->stdout_file) {
  int fd = open_for_write(cmd->stdout_file, cmd->is_file_append);
  if (fd < 0) {
    fprintf(stderr, "shell: cannot open %s (%s)\n", cmd->stdout_file, PennFatErr_toErrString(fd));
    if (close_in) s_close(redir_in);
    goto AFTER_LOOP_CLEANUP;
  }
  redir_out = fd;  close_out = true;
}


 pid_t child_pid = process_one_command(cmd->commands,
                                        cmd->num_commands,
                                         cmd->stdin_file,
                                         cmd->stdout_file,
                                         /* stderr */ NULL,
                                         cmd->is_file_append);

    if (child_pid <= 0) continue;

    if (!cmd->is_background) {            /* foreground job           */
      s_tcsetpid(child_pid);
      s_waitpid(child_pid, NULL, false);
      s_tcsetpid(shell_pgid);
    } else {
      /* TODO: store background job info */

    }

    if (close_in)  s_close(redir_in);
    if (close_out) s_close(redir_out);

    AFTER_LOOP_CLEANUP:
    ;   /* empty statement so the label isn’t alone */
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
    fprintf(stderr, "Signal <%d> sent to PID [%d].\n", signal, pid);
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
      fprintf(stderr, "%s Failed to spawn process for command: %s\n", argv[0], argv[2]);
    
    } else if (s_nice(child_pid, priority) == 0) {      // SYSTEM CALL TO UPDATE NICE VALUE
      // update nice value successful
      fprintf(stderr, "Command run as PID[%d] and set to priority %d: %s\n", child_pid, priority, argv[2]);
    } else {
      // TODO: more verbose response with errno checking
      fprintf(stderr, "Command run as PID[%d] but set priority failed: %s\n", child_pid, argv[2]);
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


    fprintf(stderr, "\033[1m");
    errno = 0;                                       /* keep EINTR       */
    bytes_read = read(STDIN_FILENO, buf, buf_len - 1);
    fprintf(stderr, "\033[0m");

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

/*  NEW built-ins: jobs / bg / fg / logout – step 7               */
void* jobs_builtin(void* arg) { jobs_list(); return NULL; }

void* bg(void* arg)
{
  char** argv = (char**)arg;
  int jid = argv[1] ? atoi(argv[1]+1) : -1;           /* %N form          */
  job_t *j = (jid > 0) ? jobs_by_jid(jid) : NULL;
  if (!j) { fprintf(stderr, "bg: job not found\n"); return NULL; }
  s_kill(j->pid, P_SIGCONT);
  j->state = JOB_RUNNING;
  fprintf(stderr, "[%d] %s &\n", j->jid, j->cmdline);
  return NULL;
}

void* fg(void* arg)
{
  char** argv = (char**)arg;
  int jid = argv[1] ? atoi(argv[1]+1) : -1;
  job_t *j = (jid > 0) ? jobs_by_jid(jid) : jobs_current_fg();
  if (!j) { fprintf(stderr, "fg: job not found\n"); return NULL; }

  s_kill(j->pid, P_SIGCONT);
  j->state = JOB_RUNNING;
  s_tcsetpid(j->pid);
  s_waitpid(j->pid, NULL, true);
  s_tcsetpid(shell_pgid);
  jobs_remove(j->pid);
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
