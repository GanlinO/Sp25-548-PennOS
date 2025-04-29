#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <sys/types.h>  // for ssize_t
#include "parser.h"

typedef struct parsed_command
    command_t;  // typedef struct parsed_command parsed_command_t;

// (For process control module)
/**
 * Check that ptr is not null, print message and exit with EXIT_FAILURE otherwise
 */
void assert_non_null(const void* const ptr, const char* const description);

/**
 * Check that val is not negative, print message and exit with EXIT_FAILURE otherwise
 */
void assert_non_negative(ssize_t val, const char* description);

// (For PennFAT module)
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
 * @return 0 on success, -1 on error/EOF
 */
int get_cmd(char* buf, size_t size);

#endif // UTILS_H