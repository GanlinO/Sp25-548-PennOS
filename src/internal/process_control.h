#ifndef PROCESS_CONTROL_H
#define PROCESS_CONTROL_H

#include "../common/pennos_types.h"  // for pid_t clock_tick_t def
#include "../util/logger.h"   // for logging requirement

/* process control block, intentional hidden implementation */
typedef struct pcb_t pcb_t;

/**
 * @brief The scheduler main logic
 * It should be run by the main thread of PennOS to periodically schedule processes to run
 */
void k_scheduler();

/**
 * @brief Create a new child process, inheriting applicable properties from the
 * parent.
 * @param if parent is NULL, will be regarded as child of INIT
 *
 * @return Reference to the child PCB. May return NULL if error occurs.
 */
pcb_t* k_proc_create(pcb_t* parent);

/**
 * @brief Create spthread with the given routine func and put it for schedule
 */
void k_set_routine_and_run(pcb_t* proc, void* (*func)(void*), char* argv[]);

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
 * Get the PCB pointer for current process
 */
pcb_t* k_get_self_pcb();

pid_t k_get_pid(pcb_t* pcb_ptr);

/**
 * Print process details
 */
void k_printprocess();

/**
 * @brief Setter of the logger for the process control module
 */
void k_set_logger(Logger* new_logger);

#endif  // PROCESS_CONTROL_H