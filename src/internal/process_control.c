#include "process_control.h"
#include "../util/spthread.h" // for spthread
#include "../util/Vec.h"      // for Vec
#include "../util/utils.h"    // for assert_non_null

#include <stdlib.h>
#include <signal.h>           // for scheduler handling SIGALRM
#include <string.h>           // for strlen and strcpy for process name

/********************
 *    definitions   *
 ********************/

#define MAX_PID_NUMBER (65535)  // largest possible PID #
#define INIT_PID (1)            // PID # of INIT

#define PRIORITY_1_WEIGHT (9)   // 1.5x than PRIORITY_2_WEIGHT
#define PRIORITY_2_WEIGHT (6)   // 1.5x than PRIORITY_3_WEIGHT
#define PRIORITY_3_WEIGHT (4)

#define MILLISECOND_IN_USEC (1000)
#define SECOND_IN_USEC (1000000)
#define CLOCK_TICK_IN_USEC (100 * MILLISECOND_IN_USEC)

#define INIT_PROCESS_NAME "INIT"
#define DEFAULT_PROCESS_NAME "(unknown)"

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
 * - waitable children PCB pointer
 * - PID of the child it is waiting for (or -1 for any); 0 for none
 * - flag for whether it is being blocked for sleep()
 * - the clock tick at which the process should be awake
 * - own wstatus if the parent calls waitpid on it
 * - file descriptors
 * - pending signals
 * - process name (for ps printing)
 */ 
struct pcb_t {
  spthread_t spthread;
  pid_t pid;
  process_state state;
  schedule_priority priority;
  pcb_t* parent;
  Vec children;
  Vec waitable_children;
  pid_t waiting_child_pid;
  bool blocked_by_sleep;
  clock_tick_t wake_tick;
  int waitpid_stat;
  Vec fds;
  signal_t pending_signals;
  char* process_name;
};

/**
 * The struct is used to pass the original func and args to the exit wrapper
 */
typedef struct routine_exit_wrapper_args_t {
  void* (*func)(void*);
  void* arg;
} routine_exit_wrapper_args_t;

/**
 * The struct is used to pass the original func and args of the starting shell to INIT
 */
typedef struct starting_shell_args_t {
  void* (*shell_func)(void*);
  void* shell_arg;
  pcb_t* init_pcb;
} starting_shell_args_t;

/********************
 * static variables *
 ********************/

// the flag for checking if the kernel has started, before the attempt to create other process
bool kernel_started = false;

// the flag to indicate that the scheduler should be shut down
bool shutdown;
// the mutex to protect shutdown
pthread_mutex_t shutdown_mtx;

clock_tick_t clock_tick;

// the pid handed out most recently
static pid_t last_pid;

// list of all processes (pcb_ptr*) with index exactly PID - 1
// this can help get the PCB pointer of a certain PID
// and also check whether a PID is available when giving out PIDs (with recycling)
// Vec is expected to initialize with element destructor function (clean_up_pcb),
// so when element is removed from Vec or when Vec is cleared/destructed, the 
// corresponding PCB struct pointed by the pcb_ptr element will be cleaned up
static Vec all_prcs;

// queues of processes (pcb_ptr*) ready for scheduling (w/ different priorities)
// used by scheduler to pick next process to run
// Vec is expected to initialize without element destructor function
// (removing the element does not trigger PCB clean up)
static Vec ready_prcs_queues [PRIORITY_COUNT];

// list of blocked processes (pcb_ptr*)
// used by the scheduler to examine blocked processes (whether they are ready
// to be unblocked) during quantum gaps
// may also contain stopped process if it is both stopped and blocked
// Vec is expected to initialize without element destructor function
// (removing the element does not trigger PCB clean up)
static Vec blocked_prcs;

// list of stopped processes (pcb_ptr*)
// may also contain stopped process if it is both stopped and blocked
// Vec is expected to initialize without element destructor function
// (removing the element does not trigger PCB clean up)
static Vec stopped_prcs;

// list of processes with pending signals
// Vec is expected to initialize without element destructor function
// (removing the element does not trigger PCB clean up)
static Vec pending_sig_prcs;

// logger
static Logger* logger = NULL;

/********************
 * declaration of internal and helper functions *
 ********************/

static void kernel_scheduler();

static void process_control_initialize();
static void create_init(void* (*starting_shell_func)(void*), void* starting_shell_arg);
static void process_control_cleanup();
static void examine_blocked_processes();

static void* init_routine(void* arg);

static pcb_t* get_pcb_at_pid(pid_t pid);
static void set_pcb_at_pid(pid_t pid, pcb_t* pcb_ptr);
static pid_t get_new_pid();
static pcb_t* create_pcb(pid_t pid, pcb_t* parent);
static void clean_up_pcb(void* pcb_void_ptr);
static pcb_t* get_pcb_by_spthread (spthread_t spthread);
static void set_routine_and_run_helper(pcb_t* proc, void* (*func)(void*), void* arg, bool wrap_exit);
static bool check_blocked_waiting_child(pcb_t* pcb);
static schedule_priority scheduler_get_next_priority();
static void set_process_name(pcb_t* pcb, const char* process_name);

static void schedule_event_log(pcb_t* proc, schedule_priority priority);
static void lifecycle_event_log(pcb_t* proc, char* event_name, char* add_msg);

static void init_adopt_children(pcb_t* pcb);
static void register_blocked_state(pcb_t* pcb);

static bool remove_pcb_first_from_vec(pcb_t* pcb_ptr, Vec* vec);
static int remove_pcb_all_from_vec(pcb_t* pcb_ptr, Vec* vec);

static void* routine_exit_wrapper_func(void* wrapped_args);
static routine_exit_wrapper_args_t* wrap_routine_exit_args(void* (*func)(void*), char* argv[]);

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
 * @brief The scheduler main logic
 * It should be run by the main thread of PennOS to periodically schedule processes to run
 */
static void kernel_scheduler() {
  // the scheduler should not be called another time
  static bool scheduler_started = false;
  if (scheduler_started) {
    logger_log(logger, LOG_LEVEL_WARN, "kernel_scheduler already run before");
    return;
  }
  scheduler_started = true;

  logger_log(logger, LOG_LEVEL_DEBUG, "start kernel_scheduler");

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

  assert_non_negative(pthread_mutex_lock(&shutdown_mtx), "Mutex lock error in kernel_scheduler");
  while (!shutdown) {
    assert_non_negative(pthread_mutex_unlock(&shutdown_mtx), "Mutex unlock error in kernel_scheduler");
    if (vec_len(&ready_prcs_queues[next_priority]) != 0) {
      // picked ready queue is not empty
      pcb_t* pcb_next_run = (pcb_t*) vec_get(&ready_prcs_queues[next_priority], 0);
      vec_erase(&ready_prcs_queues[next_priority], 0);
      if (!pcb_next_run) {
        logger_log(logger, LOG_LEVEL_ERROR, "PCB null found in queue[%d] in kernel_scheduler", next_priority);
        continue;
      }

      logger_log(logger, LOG_LEVEL_DEBUG, "PID[%d] (priority %d) picked to run by scheduler",
        pcb_next_run->pid, next_priority);
      schedule_event_log(pcb_next_run, next_priority);

      spthread_continue(pcb_next_run->spthread);
      sigsuspend(&suspend_set);
      ++clock_tick;
      spthread_suspend(pcb_next_run->spthread);

      // register async keyboard signals
      // TODO
      // process signals during this quantum
      // TODO
      // examine blocked processes
      examine_blocked_processes();

      if (pcb_next_run->state == PROCESS_STATE_READY) {
        vec_push_back(&ready_prcs_queues[pcb_next_run->priority], pcb_next_run);
      }

      next_priority = scheduler_get_next_priority();

    } else if (vec_len(&ready_prcs_queues[PRIORITY_1]) == 0 && vec_len(&ready_prcs_queues[PRIORITY_2]) == 0
          && vec_len(&ready_prcs_queues[PRIORITY_3]) == 0) {
      // all ready queue is empty
      logger_log(logger, LOG_LEVEL_DEBUG, "All queue empty!", next_priority);
      sigsuspend(&suspend_set);
      ++clock_tick;

      // register async keyboard signals
      // TODO
      // process signals during this quantum
      // TODO
      // examine blocked processes
      examine_blocked_processes();

    } else {
      logger_log(logger, LOG_LEVEL_DEBUG, "Queue[%d] empty so pass", next_priority);
      next_priority = scheduler_get_next_priority();
    }

  }
  
  logger_log(logger, LOG_LEVEL_INFO, "kernel_scheduler concludes");
}

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

  clock_tick = 0;
  last_pid = INIT_PID;              // reserve for INIT

  // initialize the process lists
  // pcb will be cleaned up only when removing a process from all_prcs
  // others will not
  all_prcs = vec_new(0, clean_up_pcb);
  blocked_prcs = vec_new(0, NULL);
  stopped_prcs = vec_new(0, NULL);
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
 * Reads in the starting shell function and its arg, create a new process with it and run.
 * Then continously wait for children until see the starting shell returns
 */
static void create_init(void* (*starting_shell_func)(void*), void* starting_shell_arg){
  static bool init_created = false;
  if (init_created) {
    return;
  }

  pcb_t* pcb_ptr = create_pcb(INIT_PID, NULL);
  assert_non_null(pcb_ptr, "pcb_ptr null in create_init");

  set_pcb_at_pid(INIT_PID, pcb_ptr);


  starting_shell_args_t* args_to_init = malloc(sizeof(starting_shell_args_t));
  args_to_init->shell_func = starting_shell_func;
  args_to_init->shell_arg = starting_shell_arg;
  args_to_init->init_pcb = pcb_ptr;
  set_routine_and_run_helper(pcb_ptr, init_routine, args_to_init, false);

  init_created = true;
  logger_log(logger, LOG_LEVEL_DEBUG, "create_init completed");
}

/**
 * Routine function of INIT
 */

static void* init_routine(void* arg) {
  logger_log(logger, LOG_LEVEL_DEBUG, "INIT routine started");

  assert_non_null(arg, "Arg null for init_routine");
  starting_shell_args_t* args_to_init = (starting_shell_args_t*) arg;

  pcb_t* starting_shell_pcb = create_pcb(get_new_pid(), args_to_init->init_pcb);
  assert_non_null(starting_shell_pcb, "Created shell PCB is null in init_routine");

  // the shell should be run with top priority
  starting_shell_pcb->priority = PRIORITY_1;
  
  const pid_t starting_shell_pid = starting_shell_pcb->pid;
  set_pcb_at_pid(starting_shell_pid, starting_shell_pcb);
  set_routine_and_run_helper(starting_shell_pcb, args_to_init->shell_func, args_to_init->shell_arg, true);
  free(arg);

  if (strcmp(starting_shell_pcb->process_name, DEFAULT_PROCESS_NAME) == 0) {
    set_process_name(starting_shell_pcb, "SHELL");
  }

  while (true) {
    pid_t waited_pid = k_waitpid(-1, NULL, false);
    if (waited_pid == starting_shell_pid) {
      logger_log(logger, LOG_LEVEL_INFO, "INIT has waited shell, will trigger shutdown");
      break;
    }
  }

  logger_log(logger, LOG_LEVEL_DEBUG, "INIT triggering shutdown");
  k_shutdown();

  logger_log(logger, LOG_LEVEL_DEBUG, "INIT routine completed");
  return NULL;
}

/**
 * Clean up the process control module metadata upon graceful shutdown
 */
// static void process_control_cleanup() {
static void process_control_cleanup() {
  logger_log(logger, LOG_LEVEL_DEBUG, "process_control_cleanup started");

  for (size_t i = 0; i < vec_len(&all_prcs); ++i) {
    pcb_t* pcb_ptr = vec_get(&all_prcs, i);
    if (pcb_ptr) {
      spthread_cancel_and_join(pcb_ptr->spthread);
      logger_log(logger, LOG_LEVEL_DEBUG, "PID[%d](%d) cancelled and joined", i + 1, pcb_ptr->pid);
    }
  }

  vec_destroy(&blocked_prcs);
  vec_destroy(&stopped_prcs);
  vec_destroy(&pending_sig_prcs);

  for (schedule_priority i = PRIORITY_1; i < PRIORITY_COUNT - 1; ++i) {
    vec_destroy(&ready_prcs_queues[i]);
  }
  logger_log(logger, LOG_LEVEL_DEBUG, "Blocked / Stopped / Signal / Ready vecs destructed");

  vec_destroy(&all_prcs);
  logger_log(logger, LOG_LEVEL_DEBUG, "all_prcs vec destructed");

  assert_non_negative(pthread_mutex_destroy(&shutdown_mtx), 
    "Error init mutex in process_control_initialize");

  logger_log(logger, LOG_LEVEL_DEBUG, "process_control_cleanup completed");

  logger_log(logger, LOG_LEVEL_DEBUG, "Closing logger");
  logger_close(logger);  

}

/**
 * Examine the current blocked processes and unblock those with block condition not longer holds
 */
static void examine_blocked_processes() {
  size_t index = 0;

  while (index < vec_len(&blocked_prcs)) {
    pcb_t* proc = vec_get(&blocked_prcs, index);
    if (!proc) {
      logger_log(logger, LOG_LEVEL_WARN, "Null PCB found in blocked_prcs in examine_blocked_processes");
      vec_erase(&blocked_prcs, index);
      continue;
    }

    if (proc->state == PROCESS_STATE_TERMINATED) {
      logger_log(logger, LOG_LEVEL_DEBUG, "Terminated PCB found in blocked_prcs in examine_blocked_processes");
      vec_erase(&blocked_prcs, index);
      continue;
    }

    // check whether still blocked by sleep
    if (proc->blocked_by_sleep) {
      if (clock_tick != proc->wake_tick) {
        // still sleeping
        ++index;
        continue;
      } else {
        // wake up time
        proc->blocked_by_sleep = false;
        proc->wake_tick = 0;
      }
    }

    // have ensured not blocked by sleep, check whether still blocked by waitpid
    
    if (check_blocked_waiting_child(proc)) {
      // still blocking on waitpid
      ++index;
      continue;
    }

    // no longer blocking
    vec_erase(&blocked_prcs, index);

    // schedule for running only if it is showing as BLOCKED previously
    // should not do so for STOPPED as they should continue to be STOPPED even when
    // the blocking condition is lifted
    if (proc->state == PROCESS_STATE_BLOCKED) {
      proc->state = PROCESS_STATE_READY;
      vec_push_back(&ready_prcs_queues[proc->priority], proc);
      logger_log(logger, LOG_LEVEL_DEBUG, "PID[%d] unblocks and ready for schedule", proc->pid);
    } else {
      logger_log(logger, LOG_LEVEL_DEBUG, "PID[%d] unblocks but still stopped", proc->pid);
    }

  }

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
    logger_log(logger, LOG_LEVEL_WARN, "Attempt to get pcb for invalid PID (<= 0)");
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
 * @param parent its parent PCB pointer
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
    .priority = PRIORITY_2,   // all processes are by default PRIORITY_2 upon birth
    .parent = NULL,
    .children = vec_new(0, NULL),
    .waitable_children = vec_new(0, NULL),
    .blocked_by_sleep = false,
    .wake_tick = 0,
    .waitpid_stat = 0,
    .fds = vec_new(0, NULL),
    .pending_signals = 0,
    .process_name = NULL
  };

  if (parent) {
    pcb_ptr->parent = parent;
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

  if (!pcb_void_ptr) {
    logger_log(logger, LOG_LEVEL_DEBUG, "clean_up_pcb called on null");
    return;
  }

  pcb_t* pcb_ptr = (pcb_t*) pcb_void_ptr;
  pid_t pid = pcb_ptr->pid;

  free(pcb_ptr->process_name);

  vec_destroy(&(pcb_ptr->children));
  vec_destroy(&(pcb_ptr->waitable_children));
  vec_destroy(&(pcb_ptr->fds));
  free(pcb_ptr);
  logger_log(logger, LOG_LEVEL_DEBUG, "clean_up_pcb completed for prev PID[%d]", pid);
}

/**
 * Find the PCB struct for the given spthread
 */
static pcb_t* get_pcb_by_spthread (spthread_t spthread) {
  for (size_t i = 0; i < vec_len(&all_prcs); ++i) {
    pcb_t* prc = (pcb_t*) vec_get(&all_prcs, i);
    if (prc != NULL && spthread_equal(prc->spthread, spthread)) {
      return prc;
    }
  }

  logger_log(logger, LOG_LEVEL_ERROR, "Not able to find spthread in get_pcb_by_spthread");
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

  routine_exit_wrapper_args_t* unwrapped_args_ptr = (routine_exit_wrapper_args_t*) wrapped_args;
  void* (*original_func) (void*) = unwrapped_args_ptr->func;
  void* original_arg = unwrapped_args_ptr->arg;

  free(wrapped_args);

  void* result = original_func(original_arg);  

  // call k_exit manually so that PCB is updated
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
static void set_routine_and_run_helper(pcb_t* proc, void* (*func)(void*), void* arg, bool wrap_exit) {
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
    routine_exit_wrapper_args_t* wrapped_args = wrap_routine_exit_args(func, arg);
    create_status = spthread_create(&(proc->spthread), NULL, routine_exit_wrapper_func, wrapped_args);
  } else {
    create_status = spthread_create(&(proc->spthread), NULL, func, arg);
  }
  assert_non_negative(create_status, "spthread create error");

  logger_log(logger, LOG_LEVEL_DEBUG, "Set routing started");

  // set up process name
  char* process_name = NULL;
  if (proc->pid ==INIT_PID) {
    process_name = INIT_PROCESS_NAME;
  } else if (arg == NULL) {
    process_name = DEFAULT_PROCESS_NAME;
  } else {
    char** argv = (char**) arg;
    process_name = argv[0];
  }

  set_process_name(proc, process_name);
  
  logger_log(logger, LOG_LEVEL_DEBUG, "Process name set for PID[%d]: %s", proc->pid, proc->process_name);

  proc->state = PROCESS_STATE_READY;
  vec_push_back(&ready_prcs_queues[proc->priority], proc);

  lifecycle_event_log(proc, "CREATED", NULL);
}

/** Helper function to check whether the process should still block
 * waiting for waiting_child_pid, by checking whether pcb->waitable_children
 * has the child it is waiting on.
 * @return true if it is waiting for a child (waiting_child_pid != 0) and
 * pcb->waitable_children does not yet have that child
 * @return false otherwise (if that child shows up in pcb->waitable_children, 
 * or it is not waiting for a child)
 */
static bool check_blocked_waiting_child(pcb_t* pcb) {
  if (!pcb) {
    return false;
  }

  pid_t waiting_pid = pcb->waiting_child_pid;

  if (waiting_pid == 0) {
    return false;
  }

  if (waiting_pid == -1) {
    return (vec_len(&pcb->waitable_children) == 0);
  }

  for (size_t i = 0; i < vec_len(&pcb->waitable_children); ++i) {
    pcb_t* child_pcb = vec_get(&pcb->waitable_children, i);
    if (!child_pcb) {
      logger_log(logger, LOG_LEVEL_ERROR, "Null PCB in waitable_children in check_blocked_waiting_child");
      continue;
    }
    if (child_pcb->pid == waiting_pid) {
      return false;
    }
  }

  return true;
}

/**
 * Have INIT adopt all children of the process pointed by pcb
 */
static void init_adopt_children(pcb_t* pcb) {
  if (!pcb) {
    return;
  }

  pcb_t* init_pcb = get_pcb_at_pid(INIT_PID);
  assert_non_null(init_pcb, "INIT PCB not found in init_adopt_children");

  for (size_t i = 0; i < vec_len(&pcb->children); ++i) {

    pcb_t* child_pcb = vec_get(&pcb->children, i);
    if (child_pcb && child_pcb->parent == pcb) {
      child_pcb->parent = init_pcb;

      vec_push_back(&init_pcb->children, child_pcb);
      logger_log(logger, LOG_LEVEL_DEBUG, "INIT adopted child PID[%d] from PID[%d]", child_pcb->pid, pcb->pid);

      lifecycle_event_log(child_pcb, "ORPHAN", NULL);
    } else {
      logger_log(logger, LOG_LEVEL_ERROR, "INIT gave up adopting child PID[%d] as not child of PID[%d]", child_pcb->pid,  pcb->pid);
    }
  }

  for (size_t i = 0; i < vec_len(&pcb->waitable_children); ++i) {
    pcb_t* child_pcb = vec_get(&pcb->waitable_children, i);
    // child's parent should already be updated to INIT
    if (child_pcb && child_pcb->parent == init_pcb) {
      vec_push_back(&init_pcb->waitable_children, child_pcb);
      logger_log(logger, LOG_LEVEL_DEBUG, "INIT added waitable child PID[%d]", child_pcb->pid);
    } else {
      logger_log(logger, LOG_LEVEL_ERROR, "Invalid PCB when INIT add waitable child PID[%d]", child_pcb->pid);
    } 
  }

  // clear children and waitable children upon adoption completion
  vec_clear(&pcb->children);
  vec_clear(&pcb->waitable_children);
}

/**
 * Helper function to register a process that becomes blocking
 * @note Does not necessarily change pcb->state to PROCESS_STATE_BLOCK if it was not READY
 * @note Not to be called standalone! Should only be called by k_sleep and k_waitpid,
 * and they are expected to set relevant metadata (wait_tick, blocked_by_sleep, waiting_child_pid)
 * themselves
 */
static void register_blocked_state(pcb_t* pcb) {
  vec_push_back(&blocked_prcs, pcb);

  if (pcb->state == PROCESS_STATE_READY) {
    pcb->state = PROCESS_STATE_BLOCKED;

    // this is usually not needed as the running process is not in ready queue
    if (remove_pcb_first_from_vec(pcb, &ready_prcs_queues[pcb->priority])) {
      logger_log(logger, LOG_LEVEL_DEBUG, "PID[%d] removed from ready queue[%d]", pcb->pid, pcb->priority);
    }
    
  }

  // no need to change state if was STOPPED or BLOCKED
  // since a stopped process should still be stopped when blocked or unblocked
  // waiting_child_pid and blocked_by_sleep will indicate whether the process should be BLOCKED
  // or READY when the stop condition is lifted (i.e. receives P_SIGCONT)
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

/**
 * Set the name of a process in PCB
 * If process_name is NULL, will set it to DEFAULT_PROCESS_NAME
 */
static void set_process_name(pcb_t* pcb, const char* process_name) {

  if (process_name == NULL) {
    logger_log(logger, LOG_LEVEL_DEBUG, "process_name null in set_process_name");
    process_name = DEFAULT_PROCESS_NAME;
  }

  free(pcb->process_name);

  pcb->process_name = malloc(strlen(process_name) + 1);
  assert_non_null(pcb->process_name, "Malloc failed for process name in set_process_name");

  strcpy(pcb->process_name, process_name);
  assert_non_null(pcb->process_name, "Strcpy failed in set_process_name");
}

/**
 * Helper function to print log the schedule events
 */
static void schedule_event_log(pcb_t* proc, schedule_priority priority) {
  if (!proc) {
    logger_log(logger, LOG_LEVEL_WARN, "PCB null in schedule_event_log");
    return;
  }
  logger_log(logger, LOG_LEVEL_DEBUG, "\t[%4d]\t%-7s\t%d\t%d\t%s",
    clock_tick, "SCHEDULE", proc->pid, priority, (proc->process_name) ? proc->process_name : "?");
}

/**
 * Helper function to print log the life cycle events
 */
static void lifecycle_event_log(pcb_t* proc, char* event_name, char* add_msg){
  if (!proc) {
    logger_log(logger, LOG_LEVEL_WARN, "PCB null in lifecycle_event_log");
    return;
  }
  logger_log(logger, LOG_LEVEL_INFO, "\t[%4d]\t%-7s\t%d\t%d\t%s %s",
    clock_tick, (event_name) ? event_name : "<EVENT>", proc->pid,
    proc->priority, (proc->process_name) ? proc->process_name : "<null>",
    (add_msg) ? add_msg : "");
}

/**
 * Helper function to find the first occurence of pcb_ptr in a Vec and remove it if found
 * @return true if found and removed; false if not found
 */
static bool remove_pcb_first_from_vec(pcb_t* pcb_ptr, Vec* vec) {
  if (!pcb_ptr || !vec) {
    logger_log(logger, LOG_LEVEL_WARN, "PCB or Vec null in remove_pcb_first_from_vec");
    return false;
  }

  for (size_t i = 0; i < vec_len(vec); ++i) {
    if (pcb_ptr == vec_get(vec, i)) {
      vec_erase(vec, i);
      return true;
    }
  }

  return false;
}

/**
 * Helper function to find the all occurences of pcb_ptr in a Vec and remove it if found
 * @return number of occurences found and removed; 0 if not found
 */
static int remove_pcb_all_from_vec(pcb_t* pcb_ptr, Vec* vec) {
  if (!pcb_ptr || !vec) {
    logger_log(logger, LOG_LEVEL_WARN, "PCB or Vec null in remove_pcb_all_from_vec");
    return 0;
  }

  int count = 0;

  for (int i = vec_len(vec) - 1; i >= 0; --i) {
    if (pcb_ptr == vec_get(vec, i)) {
      vec_erase(vec, i);
      ++count;
    }
  }

  return count;
}

/********************
 * public functions *
 ********************/

void k_kernel_start(void* (*starting_shell)(void*), void* arg) {
  // initialize the static variables of this module
  process_control_initialize();

  // create init process, which will create the starting shell
  create_init(starting_shell, arg);
  kernel_started = true;

  // start scheduler
  kernel_scheduler();

  process_control_cleanup();
}

pcb_t* k_proc_create(pcb_t* parent) {
  if (!kernel_started) {
    logger_log(logger, LOG_LEVEL_ERROR, "Failed k_proc_create: Kernel has not started");
    return NULL;
  }

  pcb_t* pcb_ptr = NULL;

  if (parent) {
    pcb_ptr = create_pcb(get_new_pid(), parent);

  } else {
    pcb_t* init_pcb_ptr = get_pcb_at_pid(1);
    assert_non_null(init_pcb_ptr, "INIT PCB not found in all_procs");

    pcb_ptr = create_pcb(get_new_pid(), init_pcb_ptr);
  }

  assert_non_null(pcb_ptr, "pcb_ptr null in k_proc_create");
  set_pcb_at_pid(pcb_ptr->pid, pcb_ptr);
  logger_log(logger, LOG_LEVEL_DEBUG, "PID[%d] PCB created and added to all_procs", pcb_ptr->pid);
  
  return pcb_ptr;
}

void k_set_routine_and_run(pcb_t* proc, void* (*func)(void*), void* arg) {
  set_routine_and_run_helper(proc, func, arg, true);
}

void k_proc_cleanup(pcb_t* proc) {
  if (proc->state != PROCESS_STATE_TERMINATED) {
    logger_log(logger, LOG_LEVEL_WARN, "k_proc_cleanup not done as process not terminated");
    return;
  }

  // join spthread
  spthread_cancel_and_join(proc->spthread);

  pcb_t* parent_pcb = proc->parent;
  assert_non_null(parent_pcb, "Parent PCB null in k_proc_cleanup");
  
  // remove from parent's child vec
  // assume waitable children has been cleaned up
  if (!remove_pcb_first_from_vec(proc, &parent_pcb->children)) {
    logger_log(logger, LOG_LEVEL_WARN, "Cannot find reaped child in k_waitpid");
  }
  // double check whether all children has gone (been adopted previously)
  if (vec_len(&proc->children) > 0 || vec_len(&proc->waitable_children) > 0) {
    logger_log(logger, LOG_LEVEL_WARN, "Unadopted orphan found in k_waitpid");
    init_adopt_children(proc);
  }
  
  // remove the pcb from all_prcs, which will automatically destruct the PCB
  pid_t my_pid = proc->pid;
  logger_log(logger, LOG_LEVEL_DEBUG, "Setting all_prcs for PID %d to NULL", my_pid);
  set_pcb_at_pid(my_pid, NULL);

}

pid_t k_waitpid(pid_t pid, int* wstatus, bool nohang) {
  if (pid < -1) {
    // TODO: set errno
    return -1;
  }

  pcb_t* child_pcb = NULL;      // pcb null indicates wait for any child in this function
  pcb_t* self_pcb = k_get_self_pcb();

  // check whether the specified PID is indeed a child
  if (pid != -1) {
    child_pcb = get_pcb_at_pid(pid);
    if (!child_pcb || child_pcb->parent != self_pcb) {
      // TODO: set errno ECHILD
      return -1;
    }
  }

  while (true) {
    // try finding this child in waitable_children
    pcb_t* waited_child = NULL;
    for (size_t i = 0; i < vec_len(&self_pcb->waitable_children); ++i) {
      pcb_t* waitable_child = vec_get(&self_pcb->waitable_children, i);
      if (waitable_child && (!child_pcb || waitable_child == child_pcb)) {
        if (waitable_child->parent != self_pcb) {
          logger_log(logger, LOG_LEVEL_WARN, "Waitable child[%d]'s parent [%d] not match waiting process [%d], waited anyway",
            waitable_child->pid, (waitable_child->parent) ? (waitable_child->parent->pid) : 0, self_pcb->pid);
        }

        waited_child = waitable_child;
        break;
      }
    }

    if (waited_child) {
      // found waited child
      logger_log(logger, LOG_LEVEL_DEBUG, "PID[%d] found waited child", self_pcb->pid);

      // successfully found child to wait for
      pid_t waited_child_pid = waited_child->pid;
      // TODO: set wstatus for EXIT stat
      if (wstatus) {
        *wstatus = waited_child->waitpid_stat;
      }
      
      // clear this child from waitable_children
      int wchd_removed = remove_pcb_all_from_vec(waited_child, &self_pcb->waitable_children);
      if (wchd_removed > 0) {
        logger_log(logger, LOG_LEVEL_DEBUG, 
          "%d PID[%d] removed from waitable_children", wchd_removed, waited_child_pid);
      } else {
        logger_log(logger, LOG_LEVEL_WARN, 
          "PID[%d] not found in waitable_children", wchd_removed, waited_child_pid);
      }

      // clear waiting child (indication of block on waitpid)
      self_pcb->waiting_child_pid = 0;

      // log lifetime event just before the pcb cleanup (as data will be lost after reaping)
      lifecycle_event_log(waited_child, "WAITED", (self_pcb->pid == INIT_PID) ? "(by init)" : NULL);

      // if waited child has terminated (zombie), reap it
      if (waited_child->state == PROCESS_STATE_TERMINATED) {
        k_proc_cleanup(waited_child);
      }

      return waited_child_pid;

    } else {
      // have not found a child to wait, register block info and block, or return 0 for nohang
      if (nohang) {
        return 0;
      }

      logger_log(logger, LOG_LEVEL_DEBUG, "PID[%d] cannot find waited child, will start blocking", self_pcb->pid);
      self_pcb->waiting_child_pid = pid;
      register_blocked_state(self_pcb);

      assert_non_negative(spthread_suspend_self(), "spthread_suspend_self error in k_waitpid");
    }
  }
}

void k_sleep(clock_tick_t ticks) {
  pcb_t* self_pcb = k_get_self_pcb();
  assert_non_null(self_pcb, "Self PCB null in k_sleep");

  if (self_pcb->state == PROCESS_STATE_TERMINATED) {
    return;
  }

  self_pcb->blocked_by_sleep = true;
  self_pcb->wake_tick = clock_tick + ticks;
  register_blocked_state(self_pcb);

  assert_non_negative(spthread_suspend_self(), "spthread_suspend_self error in k_sleep");

}

void k_exit(void) {

  pcb_t* self_pcb = k_get_self_pcb();
  assert_non_null(self_pcb, "PCB not found in k_exit");
  logger_log(logger, LOG_LEVEL_DEBUG, "PID[%d] running k_exit", self_pcb->pid);

  lifecycle_event_log(self_pcb, "EXITED", NULL);

  // add self to parent's waitable children
  if (self_pcb->parent) {
    vec_push_back(&(self_pcb->parent->waitable_children), self_pcb);
  }

  lifecycle_event_log(self_pcb, "ZOMBIE", NULL);

  // have INIT adopt all children (and waitable children)
  logger_log(logger, LOG_LEVEL_DEBUG,
    "Triggering INIT adoption in k_exit for PID[%d] (%zu children, %zu waitable_children)",
    self_pcb->pid, vec_len(&self_pcb->children), vec_len(&self_pcb->waitable_children));
  init_adopt_children(self_pcb);

  self_pcb->state = PROCESS_STATE_TERMINATED;
  
  spthread_exit(NULL);
}

void k_shutdown(void) {
  assert_non_negative(spthread_disable_interrupts_self(), "Error disable_interrupt in k_shutdown");
  assert_non_negative(pthread_mutex_lock(&shutdown_mtx), "Mutex lock error in k_shutdown");
  shutdown = true;
  assert_non_negative(pthread_mutex_unlock(&shutdown_mtx), "Mutex unlock error in k_shutdown");
  assert_non_negative(spthread_enable_interrupts_self(), "Error enable_interrupts in k_shutdown");
}

pcb_t* k_get_self_pcb() {
  spthread_t spthread;
  if (!spthread_self(&spthread)) {
    logger_log(logger, LOG_LEVEL_ERROR, "Current thread not a spthread in k_get_self_pcb");
    return NULL;
  }

  pcb_t* pcb_ptr = get_pcb_by_spthread(spthread);
  assert_non_null(pcb_ptr, "PCB not found in k_get_self_pcb");

  return pcb_ptr;
}

pid_t k_get_pid(pcb_t* pcb_ptr) {
  if (!pcb_ptr) {
    logger_log(logger, LOG_LEVEL_WARN, "Null pcb in k_get_pid");
    return -1;
  }
  return pcb_ptr->pid;
}

void k_printprocess() {
  fprintf(stderr, "PID\tPPID\tPRI\tSTAT\tCMD\n");

  for (size_t i = 0; i < vec_len(&all_prcs); ++i) {
    pcb_t* pcb_ptr = vec_get(&all_prcs, i);
    // skip the PIDs not allocated
    if (!pcb_ptr) {
      continue;
    }
    pid_t parent_pid = (pcb_ptr->parent) ? pcb_ptr->parent->pid : 0;

    char stat;
    switch (pcb_ptr->state) {
      case PROCESS_STATE_READY:
        stat = 'R';
        break;
      case PROCESS_STATE_STOPPED:
        stat = 'S';
        break;
      case PROCESS_STATE_BLOCKED:
        stat = 'B';
        break;
      case PROCESS_STATE_TERMINATED:
        stat = 'Z';
        break;
      default:
        stat = 'U';
    }

    if (pcb_ptr) {
      fprintf(stderr, "%d\t%d\t%d\t%c\t%s\n", pcb_ptr->pid, parent_pid, pcb_ptr->priority, stat, (pcb_ptr->process_name) ? pcb_ptr->process_name : "NULL!");
    }
  }
}

void k_set_logger(Logger* new_logger) {
  // check for null
  if (new_logger) {
    logger_close(logger);
    logger = new_logger;
    logger_log(logger, LOG_LEVEL_DEBUG, "new logger set in k_set_logger");
  } else {
    logger_log(logger, LOG_LEVEL_ERROR, "Attempt to set logger to NULL in process control");
  } 
}