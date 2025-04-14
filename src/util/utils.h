#ifndef UTILS_H
#define UTILS_H

#include <sys/types.h>  // for ssize_t
#include <stdio.h>      // for perror

/**
 * Check that ptr is not null, print message and exit with EXIT_FAILURE otherwise
 */
void assert_non_null(const void* const ptr, const char* const description);

/**
 * Check that val is not negative, print message and exit with EXIT_FAILURE otherwise
 */
void assert_non_negative(ssize_t val, const char* description);

#endif  // UTILS_H