#include "../src/internal/process_control.h"
#include "../src/syscall/kernel_syscall.h"
#include "../src/user/shell.h"

int main() {
  // pseudo PennOS

  Logger* logger = logger_init_stderr(LOG_LEVEL_INFO, "PROCESS CONTROL TEST");
  logger_log(logger, LOG_LEVEL_INFO, "start");
  k_set_logger(logger);

  k_kernel_start(shell_main, NULL);

  fprintf(stderr, "END\n");
}