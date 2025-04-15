#include "../src/internal/process_control.h"
#include "../src/syscall/kernel_syscall.h"
#include "../src/user/shell.h"

int main() {
  // pseudo PennOS

  Logger* logger = logger_init_stderr(LOG_LEVEL_DEBUG, "PROCESS CONTROL TEST");
  logger_log(logger, LOG_LEVEL_DEBUG, "start");
  k_set_logger(logger);

  k_set_routine_and_run(k_proc_create(NULL), shell_main, NULL);

  k_scheduler();

  fprintf(stderr, "END\n");
}