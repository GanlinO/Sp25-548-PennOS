#include "../src/internal/process_control.h"

#include <unistd.h>     // for sleep()

void* threadfunc (void*) {
  sleep(2);
  fprintf(stderr, "Calling shutdown\n");
  k_shutdown();
  return NULL;
}

int main() {
  Logger* logger = logger_init_stderr(LOG_LEVEL_DEBUG, "PROCESS CONTROL TEST");
  logger_log(logger, LOG_LEVEL_DEBUG, "start");
  k_set_logger(logger);

  k_set_routine_and_run(k_proc_create(NULL), threadfunc, NULL);

  k_scheduler();
  logger_log(logger, LOG_LEVEL_DEBUG, "end");
}