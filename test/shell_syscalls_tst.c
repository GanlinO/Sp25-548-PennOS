#include "../src/internal/process_control.h"
#include "../src/syscall/kernel_syscall.h"
#include "../src/user/shell.h"

int main() {
  // pseudo PennOS

  Logger* logger = logger_init_stderr(LOG_LEVEL_INFO, "PROCESS CONTROL TEST");
  logger_log(logger, LOG_LEVEL_INFO, "PennOS starts");
  k_set_logger(logger);

  char* args[] = {"shell", NULL};
  k_kernel_start(shell_main, args);

  fprintf(stderr, "END\n");
}
