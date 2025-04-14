#ifndef PROCESS_CONTROL_H
#define PROCESS_CONTROL_H

#include "../util/logger.h"   // for logging requirement

/* process control block, intentional hidden implementation */
typedef struct pcb_t pcb_t;

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
 * @brief The scheduler main logic
 * It should be run by the main thread of PennOS to periodically schedule processes to run
 */
void k_scheduler();

/**
 * @brief Setter of the logger for the process control module
 */
void k_set_logger(Logger* new_logger);

/**
 * @brief Unconditionally exit the calling process.
 * Will update state in PCB and also parent's waitable children
 */
void k_exit(void);

void process_control_cleanup();

#endif  // PROCESS_CONTROL_H