#ifndef PROCESS_CONTROL_H
#define PROCESS_CONTROL_H

#include "../common/pennos_types.h"  // for pid_t clock_tick_t def
#include "../common/pennos_signals.h"
#include "../util/logger.h"   // for logging requirement

/* process control block, intentional hidden implementation */
typedef struct pcb_t pcb_t;

/**
 * @brief The entry point of the process control module. The OS should call this to start
 * the kernel, set up the starting shell to be born by INIT, and start the scheduler, and have
 * the shell running in a separate process.
 * This function does not return until the shutdown of the kernel. * 
 */
void k_kernel_start(void* (*starting_shell)(void*), void* argv);

/**
 * @brief Create a new child process, inheriting applicable properties from the
 * parent.
 * @param if parent is NULL, will be regarded as child of INIT
 *
 * @return Reference to the child PCB. May return NULL if error occurs.
 * @note make sure kernel has started before this is called
 */
pcb_t* k_proc_create(pcb_t* parent);

/**
 * @brief Create spthread with the given routine func and put it for schedule
 * @return 0 on success, -2 on invalid arguments, -1 on failed spthread creation
 */
int k_set_routine_and_run(pcb_t* proc, void* (*func)(void*), void* arg);

/**
 * @brief Clean up a terminated/finished thread's resources.
 * This may include freeing the PCB, handling children, etc.
 */
void k_proc_cleanup(pcb_t* proc);

/**
 * @brief Wait on a child of the calling process, until it changes state.
 * If `nohang` is true, this will not block the calling process and return
 * immediately.
 *
 * @param pid Process ID of the child to wait for. If set to -1, wait for any child.
 * @param wstatus Pointer to an integer variable where the status will be
 * stored.
 * @param nohang If true, return immediately if no child has exited.
 * @return pid_t The process ID of the child which has changed state on success,
 * -1 on error. If nohang is set and no child to wait for, returns 0.
 * @note Error no: ECHILD if the pid specified is not a child of the caller
 */
pid_t k_waitpid(pid_t pid, int* wstatus, bool nohang);

/**
 * @brief Set the priority of the specified thread.
 *
 * @param pid Process ID of the target thread.
 * @param priority The new priorty value of the thread (0, 1, or 2)
 * @return 0 on success, -1 on failure.
 */
int k_nice(pid_t pid, int priority);

/**
 * @brief Send a signal to a particular process.
 *
 * @param pid Process ID of the target proces.
 * @param signal Signal number to be sent.
 * @return 0 on success, -1 on error.
 */
int k_kill(pid_t pid, int signal);

/**
 * @brief Suspends execution of the calling proces for a specified number of
 * clock ticks.
 *
 * This function is analogous to `sleep(3)` in Linux, with the behavior that the
 * system clock continues to tick even if the call is interrupted. The sleep can
 * be interrupted by a P_SIGTERM signal, after which the function will return
 * prematurely.
 *
 * @param ticks Duration of the sleep in system clock ticks. Must be greater
 * than 0.
 */
void k_sleep(clock_tick_t ticks);

/**
 * @brief Unconditionally exit the calling process.
 * Will update state in PCB and also parent's waitable children
 */
void k_exit(void);

/**
 * @brief Initiate the shutdown of scheduler
 */
void k_shutdown(void);

/**
 * @brief Set the terminal control to a process
 * @return 0 on success, -1 on error.
 */
int k_tcsetpid(pid_t pid);

/**
 * Get the PCB pointer for current process
 */
pcb_t* k_get_self_pcb();

/**
 * Get the PID for a PCB pointer
 * @return PID of the PCB pointed to. If pcb_ptr is null, return -1.
 */
pid_t k_get_pid(pcb_t* pcb_ptr);

/**
 * Print process details
 */
void k_printprocess();

/**
 * @brief Setter of the logger for the process control module
 */
void k_set_logger(Logger* new_logger);

/**
* Create an anonymous, *close-on-exec* pipe.
* @param fds  int[2] supplied by caller; on success fds[0]=read end, fds[1]=write end.
* @return 0 on success, –1 on error (errno is set).
*/
int k_pipe(int fds[2]);

#endif  // PROCESS_CONTROL_H