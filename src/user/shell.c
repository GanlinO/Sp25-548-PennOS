#include "shell.h"
#include "../syscall/kernel_syscall.h"
#include "../util/parser.h"
#include "../util/utils.h"

#include <stdlib.h>   // for NULL
#include <errno.h>
#include <unistd.h>   // for STDIN_FILENO, has conflict on sleep()
#include <string.h>

#define INITIAL_BUF_LEN (4096)

#define PROMPT "PennOS > "

static char* buf = NULL;
static int buf_len = 0;

static bool exit_shell = false;

typedef struct cmd_func_match_t{
  const char* cmd;
  void* (*func)(void*);
} cmd_func_match_t;

typedef void* (*thd_func_t)(void*);

cmd_func_match_t independent_funcs[] = {
  {"ps", ps},
  {"zombify", zombify},
  {"orphanify", orphanify},
  {"busy", busy},
  {NULL, NULL}
};

/*****************************************
 *    declaration of private functions   *
 *****************************************/

static struct parsed_command* read_command();
static thd_func_t get_func_from_cmd(const char * cmd_name);

[[maybe_unused]] static void debug_print(struct parsed_command*);

/*****************************************
 *          MAIN PROGRAM                 *
 *****************************************/

void* shell_main(void* arg) {
  buf_len = INITIAL_BUF_LEN;
  buf = malloc(sizeof(buf_len));
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

    thd_func_t func = get_func_from_cmd(cmd->commands[0][0]);
    if (func == NULL) {
      fprintf(stderr, "Command not recognized: %s\n", cmd->commands[0][0]);
      continue;
    }

    pid_t pid = s_spawn(func, cmd->commands[0], 0, 1);

    if (!cmd->is_background) {
      s_waitpid(pid, NULL, false);
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
  while (true) {}

  return NULL;
 }

 // TODO: add other command functions

 /******************************************
 *            SUB-ROUTINES                *
 ******************************************/

 // TODO: add other command functions

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

void* orphanify(void* arg) {
  char* args[] = {"orphan_child", NULL};
  s_spawn(orphan_child, args, 0, 1);
  return NULL;
}


/******************************************
 *       internal help functions          *
 ******************************************/

static struct parsed_command* read_command() {

  // read user input
  ssize_t bytes_read;

  bytes_read = read(STDIN_FILENO, buf, buf_len - 1);
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

static thd_func_t get_func_from_cmd(const char * cmd_name) {
  for (size_t i = 0; independent_funcs[i].cmd != NULL; ++i) {
    if (strcmp(independent_funcs[i].cmd, cmd_name) == 0) {
      return independent_funcs[i].func;
    }
  }

  return NULL;
}

static void debug_print(struct parsed_command* cmd) {

  char** cmd0 = cmd->commands[0];
  size_t idx = 0;

  fprintf(stderr, "debug_print\n");
  while (cmd0[idx]) {
    fprintf(stderr, "%zu: %s\n", idx, cmd0[idx]);
    ++idx;
  }

}