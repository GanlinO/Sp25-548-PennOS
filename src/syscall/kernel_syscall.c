#include "kernel_syscall.h"
#include "../internal/process_control.h"
#include "../util/utils.h"

pid_t s_spawn(void* (*func)(void*), char* argv[], int fd0, int fd1) {
  pcb_t* my_pcb_ptr = k_get_self_pcb();
  // TODO: return -1 and set errno instead?
  assert_non_null(my_pcb_ptr, "Self PCB not found in s_spawn");

  pcb_t* child_pcb_ptr = k_proc_create(my_pcb_ptr);
  // TODO: return -1 and set errno instead?
  assert_non_null(child_pcb_ptr, "Child PCB not created");

  // TODO: update fd0 and fd1 for child

  k_set_routine_and_run(child_pcb_ptr, func, argv);
  // TODO: handle situation where k_set_routine_and_run may fail
  // TODO: set error number for ret -1

  pid_t child_pid = k_get_pid(child_pcb_ptr);
  if (child_pid <= 0) {
    return -1;
  }

  return child_pid;
}


pid_t s_waitpid(pid_t pid, int* wstatus, bool nohang) {
  return k_waitpid(pid, wstatus, nohang);
}


int s_kill(pid_t pid, int signal) {
  // TODO
  return 0;

}


void s_exit(void) {
  k_exit();
}


int s_nice(pid_t pid, int priority) {
  if (priority >= 3) {  // PRIORITY_COUNT
    // TODO: set errno
    return -1;
  }

  return k_nice(pid, priority);
}

void s_sleep(clock_tick_t ticks) {
  k_sleep(ticks);
}

void s_printprocess(void) {
  k_printprocess();
}