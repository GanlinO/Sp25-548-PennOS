#include "shell.h"
#include "../syscall/syscall_kernel.h"
#include "../util/parser.h"
#include "../util/utils.h"

#include <stdlib.h>   // for NULL, atoi
#include <errno.h>
#include <unistd.h>   // for STDIN_FILENO and read, has conflict on sleep()
#include <string.h>

#define INITIAL_BUF_LEN (4096)

#define PROMPT "\033[1m\033[36mPennOS > \033[0m"

static char* buf = NULL;
static int buf_len = 0;

static bool exit_shell = false;

typedef void* (*thd_func_t)(void*);

typedef struct cmd_func_match_t{
  const char* cmd;
  thd_func_t func;
} cmd_func_match_t;

cmd_func_match_t independent_funcs[] = {
  {"ps", ps},
  {"zombify", zombify},
  {"orphanify", orphanify},
  {"busy", busy},
  {NULL, NULL}
};

cmd_func_match_t sub_routines[] = {
  {"nice", u_nice},
  {"nice_pid", u_nice_pid},
  {NULL, NULL}
};

/*****************************************
 *    declaration of private functions   *
 *****************************************/

static struct parsed_command* read_command();
static pid_t process_one_command(char** cmd);

static thd_func_t get_func_from_cmd(const char * cmd_name, cmd_func_match_t* func_match);
static int get_argc(char** argv);
static bool str_to_int(const char * str, int* ret_val);

[[maybe_unused]] static void debug_print_argv(char** argv);
[[maybe_unused]] static void debug_print_parsed_command(struct parsed_command*);

/*****************************************
 *          MAIN PROGRAM                 *
 *****************************************/

void* shell_main(void* arg) {
  buf_len = INITIAL_BUF_LEN;
  buf = malloc(sizeof(char) * buf_len);
  assert_non_null(buf, "Error mallocing for buf");

  struct parsed_command* cmd = NULL;

  while (!exit_shell) {
    free(cmd);

    fprintf(stderr, PROMPT);

    cmd = read_command();

    if (!cmd || cmd->num_commands == 0) {
      continue;
    }

    // fprintf(stderr, "Command arg[0]: %s\n", cmd->commands[0][0]);

    // PROCESS COMMAND
    // without pipelining, only process commands[0]
    pid_t child_pid = process_one_command(cmd->commands[0]);

    if (child_pid <= 0) {
      // no need to wait or record job if there is no new process
      continue;
    }

    // if run as foreground, wait for it as needed; if run as background, store PID for the job
    if (!cmd->is_background) {
      // foreground job
      s_waitpid(child_pid, NULL, false);
    } else {
      // backgroung job
      // TODO: store PID info in job list

    }
  }

  free(cmd);
  free(buf);

  fprintf(stderr, "Shell exits\n");
  return NULL;
}

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