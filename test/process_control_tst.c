#include "../src/internal/process_control.h"

int main() {
  Logger* logger = logger_init_stderr(LOG_LEVEL_DEBUG, "PROCESS CONTROL TEST");
  logger_log(logger, LOG_LEVEL_DEBUG, "start");
  k_set_logger(logger);
  k_scheduler();
  logger_log(logger, LOG_LEVEL_DEBUG, "end");
  process_control_cleanup();
}