#include "process_control.h"
#include "../common/pennos_types.h"  // for pid_t def
#include "../util/spthread.h" // for spthread
#include "../util/Vec.h"      // for Vec
#include "../util/utils.h"    // for assert_non_null

#include <stdlib.h>
#include <signal.h>           // for scheduler handling SIGALRM

/********************
 *    definitions   *
 ********************/

#define MAX_PID_NUMBER (65535)   // largest possible PID #
#define INIT_PID (1)

#define PRIORITY_1_WEIGHT (9)   // 1.5x than PRIORITY_2_WEIGHT
#define PRIORITY_2_WEIGHT (6)   // 1.5x than PRIORITY_3_WEIGHT
#define PRIORITY_3_WEIGHT (4)

#define MILLISECOND_IN_USEC (1000)
#define SECOND_IN_USEC (1000000)
#define CLOCK_TICK_IN_USEC (500 * MILLISECOND_IN_USEC)

#define PROCESS_CONTROL_MODULE_NAME "PROCESS_CONTROL"

typedef enum schedule_priority {
  PRIORITY_1,     // 0
  PRIORITY_2,     // 1
  PRIORITY_3,     // 2
  PRIORITY_COUNT  // 3
} schedule_priority;

typedef enum process_state {
  PROCESS_STATE_READY = 1,    // running or waiting to be scheduled
  PROCESS_STATE_STOPPED = 2,
  PROCESS_STATE_BLOCKED = 3,
  PROCESS_STATE_TERMINATED = 4,
} process_state;

/**
 * process control block
 * including information on:
 * - corresponding spthread
 * - own PID
 * - process state
 * - priority level
 * - parent PCB pointer
 * - children PCB pointer
 * - file descriptors
 * - pending signals
 * - waitable children
 * - return status ??
 */ 
struct pcb_t {
  spthread_t spthread;
  pid_t pid;
  process_state state;
  schedule_priority priority;
  pid_t parent;
  Vec children;
  Vec waitable_children;
  Vec fds;
  signal_t pending_signals;
};

typedef struct routine_exit_wrapper_args_t {
  void* (*func)(void*);
  void* arg;
} routine_exit_wrapper_args_t;

/********************
 * static variables *
 ********************/

// the flag to indicate that the scheduler should be shut down
bool shutdown;
// the mutex to protect shutdown
pthread_mutex_t shutdown_mtx;

// the pid handed out most recently
static pid_t last_pid;

// list of all processes (with index == PID - 1)
// this can help get the PCB pointer of a certain PID
// and also check whether a PID is available when giving out PIDs (with recycling)
static Vec all_prcs;

// queues of processes ready for scheduling (w/ different priorities)
static Vec ready_prcs_queues [PRIORITY_COUNT];

// list of blocked process PIDs
static Vec blocked_prcs;

// list of stopped processes
static Vec stopped_prcs;

// list of zombie processes ??
static Vec zombie_prcs;

// list of processes with pending signals
static Vec pending_sig_prcs;

// logger
static Logger* logger = NULL;

/********************
 * declaration of internal and helper functions *
 ********************/

static void process_control_initialize();
static void create_init();
static void* init_routine(void* arg);
static void process_control_cleanup();

static pcb_t* get_pcb_at_pid(pid_t pid);
static void set_pcb_at_pid(pid_t pid, pcb_t* pcb_ptr);
static pid_t get_new_pid();
static pcb_t* create_pcb(pid_t pid, pcb_t* parent);
static void clean_up_pcb(void* pcb_void_ptr);
static pcb_t* spthread_to_pcb (spthread_t spthread);
static void* routine_exit_wrapper_func(void* wrapped_args);
static routine_exit_wrapper_args_t* wrap_routine_exit_args(void* (*func)(void*), char* argv[]);
static void set_routine_and_run_helper(pcb_t* proc, void* (*func)(void*), char* argv[], bool wrap_exit);

static void spthread_cancel_and_join(spthread_t thread);

/********************
 * POSIX signal handler *
 ********************/

/**
 * SIGALRM handler to override default behavior
 * intentionally left empty 
 */
static void alarm_handler(int signum) {}

/********************
 * internal functions *
 ********************/
/**
 * Initialize the process control module if not yet initialized
 * @note does nothing when called again after the first time (has a flag the record whether
 * it has been called before)
 */
static void process_control_initialize() {
  static bool initialized = false;
  if (initialized) {
    return;
  }

  assert_non_negative(pthread_mutex_init(&shutdown_mtx, NULL), 
    "Error init mutex in process_control_initialize");

  last_pid = 0;

  // initialize the process lists
  // pcb will be cleaned up only when removing a process from all_prcs
  // others will not
  all_prcs = vec_new(0, clean_up_pcb);
  blocked_prcs = vec_new(0, NULL);
  stopped_prcs = vec_new(0, NULL);
  zombie_prcs = vec_new(0, NULL);
  zombie_prcs = vec_new(0, NULL);
  pending_sig_prcs = vec_new(0, NULL);

  for (schedule_priority i = PRIORITY_1; i < PRIORITY_COUNT - 1; ++i) {
    ready_prcs_queues[i] = vec_new(0, NULL);
  }

  // initialize logger (to stderr by default)
  if (!logger) {
    logger = logger_init_stderr(LOG_LEVEL_DEBUG, PROCESS_CONTROL_MODULE_NAME);
  }
  
  initialized = true;
  logger_log(logger, LOG_LEVEL_DEBUG, "process control initialized");
}

/**
 * Create the INIT process
 */
static void create_init() {
  static bool init_created = false;
  if (init_created) {
    return;
  }

  process_control_initialize();

  pcb_t* pcb_ptr = create_pcb(INIT_PID, NULL);
  assert_non_null(pcb_ptr, "pcb_ptr null in create_init");

  set_pcb_at_pid(INIT_PID, pcb_ptr);
  set_routine_and_run_helper(pcb_ptr, init_routine, NULL, false);

  init_created = true;
  logger_log(logger, LOG_LEVEL_DEBUG, "create_init completed");
}

/**
 * Routine function of INIT
 */

static void* init_routine(void* arg) {
  // TODO
  logger_log(logger, LOG_LEVEL_DEBUG, "INIT started");
  return NULL;
}

/**
 * Clean up the process control module metadata upon graceful shutdown
 */
// static void process_control_cleanup() {
static void process_control_cleanup() {
  logger_log(logger, LOG_LEVEL_DEBUG, "process_control_cleanup started");

  // TODO: cancel all the unfinished processes
  for (size_t i = 0; i < vec_len(&all_prcs); ++i) {
    pcb_t* pcb_ptr = vec_get(&all_prcs, i);
    if (pcb_ptr) {
      spthread_cancel_and_join(pcb_ptr->spthread);
      logger_log(logger, LOG_LEVEL_DEBUG, "PID[%d](%d) cancelled and joined", i + 1, pcb_ptr->pid);
    }
  }

  vec_destroy(&blocked_prcs);
  vec_destroy(&stopped_prcs);
  vec_destroy(&zombie_prcs);
  vec_destroy(&pending_sig_prcs);

  for (schedule_priority i = PRIORITY_1; i < PRIORITY_COUNT - 1; ++i) {
    vec_destroy(&ready_prcs_queues[i]);
  }

  vec_destroy(&all_prcs);

  assert_non_negative(pthread_mutex_destroy(&shutdown_mtx), 
    "Error init mutex in process_control_initialize");

  logger_log(logger, LOG_LEVEL_DEBUG, "process_control_cleanup completed");

  logger_close(logger);  

}

/********************
 * helper functions *
 ********************/

/**
 * Get the PCB pointer for a certain PID.
 * If the PID is invalid (non-positive), returns NULL.
 * If the PCB does not exist yet (either PID not allocated, or PID over the current size 
 * of all_prcs), returns NULL. Does not automatically adjust the size of all_prcs.
 */
static pcb_t* get_pcb_at_pid(pid_t pid) {
  if (pid <= 0) {
    logger_log(logger, LOG_LEVEL_ERROR, "Attempt to get pcb for invalid PID (<= 0)");
    return NULL;
  }

  if (pid > vec_len(&all_prcs)) {
    return NULL;
  }

  return (pcb_t*) vec_get(&all_prcs, pid - 1);
}

/**
 * Set the PCB pointer to the corresponding entry in all_prcs
 * Will overwrite if there is already a PCB pointer there
 * Do nothing if pid is invalid (non-positive or over MAX_PID_NUMBER)
 * If pcb_ptr is NULL and pid is valid, will set the corresponding entry to NULL
 * If the PID info in PCB does not match PID, will log warning but set it anyway (???)
 */
static void set_pcb_at_pid(pid_t pid, pcb_t* pcb_ptr) {
  // check PID range
  if (pid <= 0 || pid > MAX_PID_NUMBER) {
    logger_log(logger, LOG_LEVEL_ERROR, "Attempt to set pcb for invalid PID");
    return;
  }
  
  // expand the size of all_prcs if needed
  // while (pid > vec_capacity(&all_prcs)) {
  //   logger_log(logger, LOG_LEVEL_DEBUG, "pid = %d, all_prcs_capacity = %d", pid, vec_len(&all_prcs));
  //   expand_all_prcs_vec_capacity();
  // }

  // check for PID in PCB
  if (pcb_ptr && pcb_ptr->pid != pid) {
    logger_log(logger, LOG_LEVEL_WARN, "PID mismatch in set_pcb_at_pid");
  }
  vec_set_force(&all_prcs, pid - 1, pcb_ptr);
}

/**
 * Give the next available PID.
 * Should always offer the increment of the last given PID, unless MAX_PID_NUMBER is reached (then will
 * recycle from the beginning and find the next available one).
 * Does not adjust all_prcs size automatically.
 * @post last_pid will be updated regardless the given PID is used or not.
 * @return the next available PID
 * @return -1 if no available PID anymore (max number of processes reached)
 */
static pid_t get_new_pid() {
  // make sure the initial value of last_pid is valid
  if (last_pid < 0) {
    last_pid = 0;
  }

  pid_t new_pid = last_pid;
  // find the next available PID
  do {
    new_pid = (new_pid + 1) % (MAX_PID_NUMBER + 1);
    if (new_pid == 0) {
      // should not use 0
      ++new_pid;
    }

    if (new_pid == last_pid) {
      // have gone one cycle, PID all occupied
      logger_log(logger, LOG_LEVEL_ERROR, 
        "Fatal error: PID numbers full - max number of processes reached");
      return -1;
    }
  } while (get_pcb_at_pid(new_pid));

  last_pid = new_pid;
  return last_pid;
}

/**
 * @brief Prepare the PCB struct on heap and return the pointer to it.
 * @param pid its given pid
 * @param parent its parent PCB pointer; if it is NULL, pcb->parent will be set to 0
 * @pre pid must be in range (1 to MAX_PID_NUMBER)
 * @pre if parent is not NULL, parent->pid must be in range
 * @return the pointer to the PCB created
 * @return NULL if pid is invalid
 * @note spthread in PCB is not yet set (NULL)
 * @note it is not set to all_prcs, so do not lose the pointer before that 
 * to avoid memory leakage
 * @note pcb->state will be set to 0, pcb->priority will be default to PRIORITY_2
 */
static pcb_t* create_pcb(pid_t pid, pcb_t* parent) {
  if (pid <= 0 || pid > MAX_PID_NUMBER) {
    return NULL;
  }

  if (parent) {
    if (parent->pid <= 0 || parent->pid > MAX_PID_NUMBER) {
      logger_log(logger, LOG_LEVEL_ERROR, "Parent PID out of range in create_pcb");
      return NULL;
    } 
  }

  pcb_t* pcb_ptr = (pcb_t*) malloc (sizeof(pcb_t));
  assert_non_null(pcb_ptr, "Failed malloc in create_pcb");

  *pcb_ptr = (pcb_t) {
    // .spthread not set yet
    .pid = pid,
    .state = 0,
    .priority = PRIORITY_2,
    .parent = 0,
    .children = vec_new(0, NULL),
    .waitable_children = vec_new(0, NULL),
    .fds = vec_new(0, NULL),
    .pending_signals = 0
  };

  if (parent) {
    pcb_ptr->parent = parent->pid;
    pcb_ptr->fds = parent->fds;
    vec_push_back(&(parent->children), pcb_ptr);
  } 
  return pcb_ptr;
}

/**
 * Clean up the PCB content and itself
 */
static void clean_up_pcb(void* pcb_void_ptr) {
  // ?? anything cleanup needed for spthread?

  pcb_t* pcb_ptr = (pcb_t*) pcb_void_ptr;
  vec_destroy(&(pcb_ptr->children));
  vec_destroy(&(pcb_ptr->waitable_children));
  vec_destroy(&(pcb_ptr->fds));
  free(pcb_ptr);
  logger_log(logger, LOG_LEVEL_DEBUG, "clean_up_pcb completed");
}

/**
 * Find the PCB struct for the given spthread
 */
static pcb_t* spthread_to_pcb (spthread_t spthread) {
  for (size_t i = 0; i < vec_len(&all_prcs); ++i) {
    pcb_t* prc = (pcb_t*) vec_get(&all_prcs, i);
    if (prc != NULL && spthread_equal(prc->spthread, spthread)) {
      return prc;
    }
  }

  logger_log(logger, LOG_LEVEL_ERROR, "Not able to find spthread in spthread_to_pcb");
  return NULL;
}

/**
 * A wrapper function that add k_exit to the function called
 */
static void* routine_exit_wrapper_func(void* wrapped_args) {
  if (!wrapped_args) {
    logger_log(logger, LOG_LEVEL_ERROR, "Args null in routine_exit_wrapper");
    return NULL;
  }

  routine_exit_wrapper_args_t* args = (routine_exit_wrapper_args_t*) wrapped_args;
  void* result = args->func(args->arg);

  free(wrapped_args);

  // call k_exit manually so that PCB is updated
  logger_log(logger, LOG_LEVEL_DEBUG, "Trigger k_exit at end of routine");
  k_exit();

  return result;

}

/**
 * A helper function to wrap func and argv to routine_exit_wrapper_args_t for 
 * routine_exit_wrapper_func()
 */
static routine_exit_wrapper_args_t* wrap_routine_exit_args(void* (*func)(void*), char* argv[]) {

  routine_exit_wrapper_args_t* wrapped_args = malloc(sizeof(routine_exit_wrapper_args_t));
  assert_non_null(wrapped_args, "Failed args malloc in k_set_routine_and_run");

  wrapped_args->func = func;
  wrapped_args->arg = argv;

  return wrapped_args;
}

/**
 * A helper function for k_set_routine_and_run
 */
static void set_routine_and_run_helper(pcb_t* proc, void* (*func)(void*), char* argv[], bool wrap_exit) {
  if (!proc) {
    logger_log(logger, LOG_LEVEL_ERROR, "pcb ptr is NULL for k_set_routine_and_run");
    return;
  }

  if (!func) {
    logger_log(logger, LOG_LEVEL_ERROR, "func is NULL for k_set_routine_and_run");
    return;
  }

  int create_status;

  if (wrap_exit) {
    routine_exit_wrapper_args_t* wrapped_args = wrap_routine_exit_args(func, argv);
    create_status = spthread_create(&(proc->spthread), NULL, routine_exit_wrapper_func, wrapped_args);
  } else {
    create_status = spthread_create(&(proc->spthread), NULL, func, argv);
  }
  assert_non_negative(create_status, "spthread create error");

  proc->state = PROCESS_STATE_READY;
  vec_push_back(&ready_prcs_queues[proc->priority], proc);
}

/**
 * Cancel and join a spthread
 */
static void spthread_cancel_and_join(spthread_t thread) {
  spthread_cancel(thread);
  spthread_continue(thread);
  spthread_suspend(thread); // forces the spthread to hit a cancellation point
  spthread_join(thread, NULL);
}

/**
 * Helper function to get the next priority level for scheduling based on priority weighting
 */
static schedule_priority scheduler_get_next_priority() {
  static const int weight[PRIORITY_COUNT] = {PRIORITY_1_WEIGHT, PRIORITY_2_WEIGHT, PRIORITY_3_WEIGHT};
  static const int total_weight = PRIORITY_1_WEIGHT + PRIORITY_2_WEIGHT + PRIORITY_3_WEIGHT;
  static int ticket[PRIORITY_COUNT] = {0};

  #ifdef SCHEDULER_COUNTER_ON
  static int overall = 0;
  static int real_cnt[3] = {0};
  ++overall;
  #endif

  schedule_priority next = PRIORITY_1;
  ticket[PRIORITY_1] += weight[PRIORITY_1];
  int max_ticket = weight[PRIORITY_1];

  for (schedule_priority i = PRIORITY_2; i < PRIORITY_COUNT; ++i) {
    ticket[i] += weight[i];

    if (ticket[i] > max_ticket) {
      max_ticket = ticket[i];
      next = i;
    }
  }

  // the one currently with max ticket will be the next priority
  ticket[next] -= total_weight;

  #ifdef SCHEDULER_COUNTER_ON
  ++real_cnt[next];
  fprintf(stderr, "[%d]\t%d\t%3d %3d %3d\t%3d %3d %3d\t%0.2f %0.2f\n", 
    overall, next, ticket[0], ticket[1], ticket[2],
    real_cnt[0], real_cnt[1], real_cnt[2],
    (double) real_cnt[0] / real_cnt[1], (double) real_cnt[1] / real_cnt[2]
  );
  #endif

  return next;
}

/********************
 * public functions *
 ********************/

 void k_scheduler() {
  // the scheduler should not be called another time
  static bool scheduler_started = false;
  if (scheduler_started) {
    return;
  }
  scheduler_started = true;

  logger_log(logger, LOG_LEVEL_DEBUG, "start k_scheduler");
  create_init();

  // mask for while scheduler is waiting for alarm to go off
  // block all other signals
  sigset_t suspend_set;
  sigfillset(&suspend_set);
  sigdelset(&suspend_set, SIGALRM);

  // register an empty handler so that default disposition is overridden
  struct sigaction act = (struct sigaction){
      .sa_handler = alarm_handler,
      .sa_mask = suspend_set,
      .sa_flags = SA_RESTART,
  };
  sigaction(SIGALRM, &act, NULL);

  // make sure SIGALRM is unblocked
  sigset_t alarm_set;
  sigemptyset(&alarm_set);
  sigaddset(&alarm_set, SIGALRM);
  pthread_sigmask(SIG_UNBLOCK, &alarm_set, NULL);

  struct itimerval it;
  it.it_interval = (struct timeval){
    .tv_sec = CLOCK_TICK_IN_USEC / SECOND_IN_USEC,
    .tv_usec = CLOCK_TICK_IN_USEC % SECOND_IN_USEC
  };
  it.it_value = it.it_interval;
  setitimer(ITIMER_REAL, &it, NULL);

  schedule_priority next_priority = scheduler_get_next_priority();

  assert_non_negative(pthread_mutex_lock(&shutdown_mtx), "Mutex lock error in k_scheduler");
  while (!shutdown) {
    assert_non_negative(pthread_mutex_unlock(&shutdown_mtx), "Mutex unlock error in k_scheduler");
    if (vec_len(&ready_prcs_queues[next_priority]) != 0) {
      // picked ready queue is not empty
      pcb_t* pcb_next_run = (pcb_t*) vec_get(&ready_prcs_queues[next_priority], 0);
      vec_erase(&ready_prcs_queues[next_priority], 0);
      if (!pcb_next_run) {
        logger_log(logger, LOG_LEVEL_ERROR, "PCB null found in queue[%d] in k_scheduler", next_priority);
        continue;
      }

      logger_log(logger, LOG_LEVEL_DEBUG, "PID[%d] (priority %d) picked to run by scheduler",
        pcb_next_run->pid, next_priority);

      spthread_continue(pcb_next_run->spthread);
      sigsuspend(&suspend_set);
      spthread_suspend(pcb_next_run->spthread);

      if (pcb_next_run->state == PROCESS_STATE_READY) {
        vec_push_back(&ready_prcs_queues[pcb_next_run->priority], pcb_next_run);
      }
    } else if (vec_len(&ready_prcs_queues[PRIORITY_1]) == 0 && vec_len(&ready_prcs_queues[PRIORITY_2]) == 0
    && vec_len(&ready_prcs_queues[PRIORITY_3]) == 0) {
      // all ready queue is empty
      logger_log(logger, LOG_LEVEL_DEBUG, "All queue empty!", next_priority);
      sigsuspend(&suspend_set);
      continue;
    } else {
      logger_log(logger, LOG_LEVEL_DEBUG, "Queue[%d] empty so pass", next_priority);
    }

    next_priority = scheduler_get_next_priority();
  }

  process_control_cleanup();
}

pcb_t* k_proc_create(pcb_t* parent) {
  create_init();

  pcb_t* pcb_ptr;

  if (parent) {
    pcb_ptr = create_pcb(get_new_pid(), parent);

  } else {
    pcb_t* init_pcb_ptr = get_pcb_at_pid(1);
    if (!init_pcb_ptr) {
      logger_log(logger, LOG_LEVEL_ERROR, "INIT PCB not found in all_procs");
      return NULL;
    }

    pcb_ptr = create_pcb(get_new_pid(), init_pcb_ptr);
  }

  assert_non_null(pcb_ptr, "pcb_ptr null in k_proc_create");
  set_pcb_at_pid(pcb_ptr->pid, pcb_ptr);
  logger_log(logger, LOG_LEVEL_DEBUG, "PID[%d] PCB created and added to all_procs", pcb_ptr->pid);
  
  return pcb_ptr;
}

void k_set_routine_and_run(pcb_t* proc, void* (*func)(void*), char* argv[]) {
  set_routine_and_run_helper(proc, func, argv, true);
}

void k_proc_cleanup(pcb_t* proc) {
  // TODO
}

void k_exit(void) {

  spthread_t spthread;
  if (!spthread_self(&spthread)) {
    logger_log(logger, LOG_LEVEL_ERROR, "Current thread not a spthread in k_exit");
    return;
  }

  pcb_t* pcb_ptr = spthread_to_pcb(spthread);
  assert_non_null(pcb_ptr, "PCB not found in k_exit");
  pcb_ptr->state = PROCESS_STATE_TERMINATED;

  pcb_t* parent_ptr = get_pcb_at_pid(pcb_ptr->parent);
  assert_non_null(pcb_ptr, "Parent PCB not found in k_exit");
  vec_push_back(&(parent_ptr->waitable_children), pcb_ptr);

  spthread_exit(NULL);
}

void k_shutdown(void) {
  assert_non_negative(spthread_disable_interrupts_self(), "Error disable_interrupt in k_shutdown");
  assert_non_negative(pthread_mutex_lock(&shutdown_mtx), "Mutex lock error in k_shutdown");
  shutdown = true;
  assert_non_negative(pthread_mutex_unlock(&shutdown_mtx), "Mutex unlock error in k_shutdown");
  assert_non_negative(spthread_enable_interrupts_self(), "Error enable_interrupts in k_shutdown");
}


void k_set_logger(Logger* new_logger) {
  // check for null
  if (new_logger) {
    free(logger);
    logger = new_logger;
    logger_log(logger, LOG_LEVEL_DEBUG, "new logger set in k_set_logger");
  } else {
    logger_log(logger, LOG_LEVEL_ERROR, "Attempt to set logger to NULL in process control");
  } 
}