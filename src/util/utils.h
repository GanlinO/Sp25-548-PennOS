#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include "parser.h"

typedef struct parsed_command
    command_t;  // typedef struct parsed_command parsed_command_t;

/**
 * Execute parse_command() and handles its errors, if any.
 * @param cmd_line The command line to parse.
 * @param result Pointer to the command_t structure where the result will be
 * stored.
 * @return 0 on success, -1 on error
 * @post exit(EXIT_FAILURE) if a system error occurs.
 */
int safe_parse_command(const char* cmd_line, command_t** cmd);

/**
 * Print the prompt to the standard output.
 * @param prompt The prompt string to print.
 */
void prompt(const char* prompt);

/**
 * Read a command line from the standard input.
 * @param buf The buffer to store the command line.
 * @param size The size of the buffer.
 */
void get_cmd(char* buf, size_t size);

#endif // UTILS_H