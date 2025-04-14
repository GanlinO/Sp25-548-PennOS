#include "shell.h"
#include "../syscall/kernel_syscall.h"

#include <stdlib.h>   // for NULL

void* zombie_child(void* arg) {
  // do nothing and exit right away intentionally
  return NULL;
}

void* zombify(void* arg) {
  // char* args[] = {NULL};
  // s_spawn(zombie_child, args, 0, 1);
  while (1);
  return NULL;
}

void* orphan_child(void* arg) {
  // spinning intentionally
  while (1);
  return NULL;
}

void* orphanify(void* arg) {
  // char* args[] = {NULL};
  // s_spawn(orphan_child, args, 0, 1);
  return NULL;
}

// TODO