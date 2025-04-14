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