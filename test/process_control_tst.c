#include "../src/internal/process_control.h"
#include "../src/syscall/kernel_syscall.h"

#include <unistd.h>     // for sleep()

void* func2 (void*);
void* func3 (void*);
void* func4 (void*);

// void* thdfunc (void*) {
//   sleep(2);
//   k_printprocess();
//   fprintf(stderr, "Calling shutdown\n");
//   k_shutdown();
//   return NULL;
// }

void* func2 (void*) {
  s_spawn(func3, (char**) {NULL}, 0, 1);
  fprintf(stderr, "func2 ps 1\n");
  k_printprocess();
  s_sleep(1);
  fprintf(stderr, "func2 ps 2\n");
  k_printprocess();
  s_waitpid(-1, NULL, false);
  fprintf(stderr, "func2 ps 3\n");
  k_printprocess();
  return NULL;
}

void* func3 (void*) {
  s_sleep(2);
  s_spawn(func4, (char**) {NULL}, 0, 1);
  fprintf(stderr, "func3 ps\n");
  k_printprocess();
  return NULL;
}

void* func4 (void*) {
  s_sleep(10);
  k_printprocess();
  s_sleep(5);
  fprintf(stderr, "Calling shutdown\n");
  k_shutdown();
  return NULL;
}

int main() {
  Logger* logger = logger_init_stderr(LOG_LEVEL_DEBUG, "PROCESS CONTROL TEST");
  logger_log(logger, LOG_LEVEL_DEBUG, "start");
  k_set_logger(logger);

  k_set_routine_and_run(k_proc_create(NULL), func2, NULL);

  k_scheduler();

  fprintf(stderr, "END\n");
}