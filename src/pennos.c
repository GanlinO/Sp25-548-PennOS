#include "internal/process_control.h"
#include "syscall/kernel_syscall.h"
#include "user/shell.h"

int main(int argc, char *argv[]) {

  /* PARSE AGRS FOR PENNFAT FILESYSTEM NAME AND LOG FILE NAME */
  // TODO

  /* MOUNT PENNFAT */
  // TODO

  /* RUN KERNEL (incl. INIT creation, run scheduler, spawn shell) */
  Logger* logger = logger_init_stderr(LOG_LEVEL_DEBUG, "KERNEL");
  k_set_logger(logger);
  logger_log(logger, LOG_LEVEL_INFO, "PennOS starts");
  char* args[] = {"shell", NULL};
  k_kernel_start(shell_main, args);
  // this will keep running until shell shuts down, logger will also be closed

  /* CLEAN UP AND SHUT DOWN */
  // kernel cleanup handled inside k_kernel_start()

}