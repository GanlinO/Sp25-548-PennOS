#include "utils.h"
#include "panic.h"
#include <stdlib.h>

void assert_non_null(const void* const ptr, const char* description) {
  if (ptr) {
    return;
  }
  if (description) {
    perror(description);
  }
  panic("non-null assertion failed");
}

void assert_non_negative(ssize_t val, const char* description) {
  if (val >= 0) {
    return;
  }
  if (description) {
    perror(description);
  }
  panic("non-negative assertion failed");
}

void prompt(const char *prompt) {
    printf("%s", prompt);
    fflush(stdout);
}

int get_cmd(char *buf, size_t size) {
    if (fgets(buf, size, stdin) == NULL) {
        return -1;
    }
    return 0;
}

int safe_parse_command(const char* line, command_t** cmd) {
    int parser_err = parse_command(line, cmd);
  
    if (parser_err == -1) {
        perror("!!!parse_command error!!!");
        exit(EXIT_FAILURE);
    }
  
    if (parser_err != 0) {
        /* No memory allocated for cmd on error */
        printf("Invalid Input:");
        print_parser_errcode(stdout, parser_err);
        return -1;
    }
  
    return 0;
}