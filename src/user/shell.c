#include "shell.h"
#include "../syscall/syscall_kernel.h"
#include "../common/pennos_signals.h"
#include "../util/parser.h"
#include "../util/utils.h"

#include "../internal/pennfat_kernel.h"
#include "../common/pennfat_definitions.h"

#include <stdlib.h>   // NULL, atoi
#include <errno.h>
#include <unistd.h>   // STDIN_FILENO / read
#include <string.h>
#include <ctype.h>    // isdigit (for sleep)

void* touch(void* arg);
void* ls(void* arg);
void* cat(void* arg);
void* chmod_file(void* arg);
void* cp_file(void* arg);      /* NEW */
void* mv_file(void* arg);      /* NEW */
void* rm_file(void* arg);      /* NEW */

/*──────────────────────────────────────────────────────────────*/
/*  Dispatch tables                                             */
/*──────────────────────────────────────────────────────────────*/

typedef void* (*thd_func_t)(void*);

typedef struct cmd_func_match_t{
  const char* cmd;
  thd_func_t  func;
} cmd_func_match_t;

/*  independent (straight-line) built-ins – run *inside* shell  */
cmd_func_match_t independent_funcs[] = {
  {"ps",        ps},
  {"echo",      echo},
  {"sleep",     u_sleep},      /* user types “sleep 10”          */
  {"touch",     touch},    /* NEW */
  {"ls",        ls},       /* NEW */
  {"cat",       cat},      /* NEW */
  {"chmod",     chmod_file}, /* NEW – name differs from syscall chmod(2) */
  {"zombify",   zombify},
  {"orphanify", orphanify},
  {"busy",      busy},
  {"kill",      kill},
  {"man",       man},
  {"cp",   cp_file},     /* NEW – data-moving */
  {"mv",   mv_file},     /* NEW – data-moving */
  {"rm",   rm_file},     /* NEW – data-moving */
  {NULL, NULL}
};

/*  sub-routines that *wrap* another command / pid              */
cmd_func_match_t sub_routines[] = {
  {"nice",      u_nice},
  {"nice_pid",  u_nice_pid},
  {NULL, NULL}
};

/*──────────────────────────────────────────────────────────────*/
/*          MAIN PROGRAM (existing content remains)             */
/*──────────────────────────────────────────────────────────────*/

#define INITIAL_BUF_LEN (4096)
#define PROMPT "\033[1m\033[36mPennOS > \033[0m"

static char* buf = NULL;
static int   buf_len = 0;
static bool  exit_shell = false;

static struct parsed_command* read_command();
static pid_t process_one_command(char** cmd);

static thd_func_t get_func_from_cmd(const char * cmd_name, cmd_func_match_t* table);
static int  get_argc(char** argv);
static bool str_to_int(const char * str, int* ret_val);

[[maybe_unused]] static void debug_print_argv(char** argv);
[[maybe_unused]] static void debug_print_parsed_command(struct parsed_command*);

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
    PennFatErr err = k_touch(argv[i]);
    if (err) fprintf(stderr, "touch: %s: %s\n", argv[i],
                     PennFatErr_toErrString(err));
  }
  return NULL;
}

/* ---------- ls (no arguments, PennFAT root only) ---------- */
void* ls(void* arg)
{
  (void)arg;          /* unused */
  PennFatErr err = k_ls();
  if (err) fprintf(stderr, "ls: %s\n", PennFatErr_toErrString(err));
  return NULL;
}

/* ---------- chmod ---------- */
static uint8_t parse_perm_string(const char* s)
{
  uint8_t p = 0;
  for (; *s; ++s) {
    if (*s=='r') p |= PERM_READ;
    else if (*s=='w') p |= PERM_WRITE;
    else if (*s=='x') p |= PERM_EXEC;
    else return 0xFF;          /* invalid */
  }
  return p;
}

void* chmod_file(void* arg)
{
  char** argv = (char**)arg;
  if (!argv || !argv[1] || !argv[2]) {
    fprintf(stderr, "chmod: usage: chmod PERMS FILE …\n");
    return NULL;
  }
  uint8_t perm = parse_perm_string(argv[1]);
  if (perm == 0xFF) {
    fprintf(stderr, "chmod: invalid permission string '%s'\n", argv[1]);
    return NULL;
  }
  for (int i = 2; argv[i]; ++i) {
    PennFatErr err = k_chmod(argv[i], perm);
    if (err) fprintf(stderr, "chmod: %s: %s\n", argv[i],
                     PennFatErr_toErrString(err));
  }
  return NULL;
}

/* ---------- cat (read files from PennFAT, print to stdout) ---------- */
#define CAT_BUFSZ 4096
void* cat(void* arg)
{
  char** argv = (char**)arg;
  if (!argv || !argv[1]) {
    fprintf(stderr, "cat: missing file operand\n");
    return NULL;
  }
  char buf[CAT_BUFSZ];

  for (int i = 1; argv[i]; ++i) {
    int fd = k_open(argv[i], K_O_RDONLY);
    if (fd < 0) {
      fprintf(stderr, "cat: %s: %s\n", argv[i],
              PennFatErr_toErrString(fd));
      continue;
    }
    while (1) {
      PennFatErr r = k_read(fd, CAT_BUFSZ, buf);
      if (r < 0) { fprintf(stderr, "cat: read error\n"); break; }
      if (r == 0) break;
      fwrite(buf, 1, r, stdout);
    }
    k_close(fd);
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

/*======================================================================*/
/*  Data-moving built-ins: cp / mv / rm                                 */
/*======================================================================*/

/* cp  SRC DST  — copy a file inside PennFAT (no host –h support yet) */
void* cp_file(void* arg)
{
  char** argv = (char**)arg;
  if (!argv || !argv[1] || !argv[2]) {
    fprintf(stderr, "cp: usage: cp SRC DST\n");
    return NULL;
  }

  const char* src = argv[1];
  const char* dst = argv[2];

  int src_fd = k_open(src, K_O_RDONLY);
  if (src_fd < 0) {
    fprintf(stderr, "cp: cannot open %s\n", src);
    return NULL;
  }
  int dst_fd = k_open(dst, K_O_CREATE | K_O_WRONLY);
  if (dst_fd < 0) {
    fprintf(stderr, "cp: cannot create %s\n", dst);
    k_close(src_fd);
    return NULL;
  }

  char buf[4096];
  while (1) {
    PennFatErr n = k_read(src_fd, sizeof buf, buf);
    if (n < 0) { fprintf(stderr, "cp: read error\n"); break; }
    if (n == 0) break;                 /* EOF */
    if (k_write(dst_fd, buf, n) != n) {
      fprintf(stderr, "cp: write error\n");
      break;
    }
  }

  k_close(src_fd);
  k_close(dst_fd);
  return NULL;
}

/* mv  SRC DST  — rename inside PennFAT */
void* mv_file(void* arg)
{
  char** argv = (char**)arg;
  if (!argv || !argv[1] || !argv[2]) {
    fprintf(stderr, "mv: usage: mv SRC DST\n");
    return NULL;
  }

  if (k_rename(argv[1], argv[2]) != 0)
    fprintf(stderr, "mv: cannot rename %s -> %s\n", argv[1], argv[2]);
  return NULL;
}

/* rm  FILE…  — delete one or more files */
void* rm_file(void* arg)
{
  char** argv = (char**)arg;
  if (!argv || !argv[1]) {
    fprintf(stderr, "rm: usage: rm FILE...\n");
    return NULL;
  }

  for (int i = 1; argv[i]; ++i) {
    if (k_unlink(argv[i]) != 0)
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
  pid_t shell_pid = s_getselfpid();
  assert_non_negative(shell_pid, "Shell PID invalid");

  while (!exit_shell) {
    free(cmd);

    fprintf(stderr, PROMPT);
    cmd = read_command();
    if (!cmd || cmd->num_commands == 0) continue;

    pid_t child_pid = process_one_command(cmd->commands[0]);

    if (child_pid <= 0) continue;

    if (!cmd->is_background) {            /* foreground job           */
      s_tcsetpid(child_pid);
      s_waitpid(child_pid, NULL, false);
      s_tcsetpid(shell_pid);
    } else {
      /* TODO: store background job info */
    }
  }

  free(cmd);
  free(buf);
  fprintf(stderr, "Shell exits\n");
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

void* kill(void* arg) {
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


/******************************************
 *       internal help functions          *
 ******************************************/

static struct parsed_command* read_command() {

  // read user input
  ssize_t bytes_read;

  fprintf(stderr, "\033[1m");
  bytes_read = read(STDIN_FILENO, buf, buf_len - 1);
  fprintf(stderr, "\033[0m");
  if (bytes_read >= 0) {
    buf[bytes_read] = '\0';
  }

  // reaching EOF (and just CTRL-D in terminal)
  if (bytes_read == 0) {
    fprintf(stderr, "\n");
    exit_shell = true;
    return NULL;    // success
  }

  // having error
  if (bytes_read < 0) {
    // interrupted by signal
    if (errno == EINTR) {
      return NULL;
    }
    perror("shell_loop: error read input");
    exit_shell = true;
    return NULL;    // failure
  }

  // empty line
  if (bytes_read == 1 && buf[bytes_read - 1] == '\n') {
    return NULL;
  }

  // parse command
  struct parsed_command* pcmd_ptr = NULL;
  int parse_ret = parse_command(buf, &pcmd_ptr);
  if (parse_ret != 0) {
    // invalid command
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

/**
 * Process one single command, while it can be either independent command or subroutine
 * @param cmd an array of c-strings with cmd[0] being the command name and the rest being its 
 * arguments, terminated by NULL.
 * @return the pid of the spawned process if a process is spawned. 0 if no process is spawned 
 * (for example, run as a subroutine). Negative number if there is an error.
 * @note Note that `nice` may spawn a separate process though it is run as a subroutine itself.
 */

static pid_t process_one_command(char** cmd) {
  if (cmd == NULL || cmd[0] == NULL) {
    fprintf(stderr, "Error: Null command.\n");
    return -2;
  }

  pid_t child_pid = 0;
  thd_func_t func = get_func_from_cmd(cmd[0], independent_funcs);

  if (func != NULL) {
    // FOUND INDEPENDENT FUNC COMMAND
    // spawn new process to run the command
    // TODO: do we need to update fds
    child_pid = s_spawn(func, cmd, 0, 1);
    if (child_pid < 0) {
      fprintf(stderr, "%s Error: spawn failed.\n", cmd[0]);
    }

  } else {
    // command not found as independent command
    // try as subroutine
    thd_func_t func = get_func_from_cmd(cmd[0], sub_routines);
    if (func != NULL) {

      // FOUND SUBROUTINE
      // run the subroutine directly
      void* ret = func(cmd);

      // special processing for u_nice as it also spawns process and is expected to return PID
      if (func == u_nice && ret != NULL) {
        // get pid
        pid_t* ret_pid = (pid_t*) ret;
        child_pid = *ret_pid;
      }

      free(ret);

    } else {
      // COMMAND DOES NOT EXIST
      fprintf(stderr, "Command not recognized: %s\n", cmd[0]);
    }
  }
  return child_pid;
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