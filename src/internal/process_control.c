#include "process_control.h"
#include "../util/spthread.h" // for spthread
#include "../util/Vec.h"      // for Vec
#include "../util/utils.h"    // for assert_non_null
#include "k_syscalls.h"
#include "../internal/pennfat_kernel.h"

#include <stdlib.h>
#include <signal.h>           // for scheduler handling SIGALRM
#include <string.h>           // for strlen and strcpy for process name
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>

/********************
 *    definitions   *
 ********************/

/* ------------------------------------------------------------------+
|  Child-wrapper built by s_spawn() (user land).  Kernel only needs  |
|  to know the field offsets, so we duplicate the tiny definition    |
|  here instead of including the user header (would introduce cycles)|
+-------------------------------------------------------------------*/
struct spawn_wrapper_arg {
  void *(*func)(void *);   /* child entry                            */
  void  *real_arg;         /* original argv[]                        */
  int    fd0;              /* inherited stdin  (or –1)               */
  int    fd1;              /* inherited stdout (or –1)               */
};

void *spawn_entry_wrapper(void *raw);   /* symbol lives in user land */

#define MAX_PID_NUMBER (65535)  // largest possible PID #
#define INIT_PID (1)            // PID # of INIT

#define PRIORITY_1_WEIGHT (9)   // 1.5x than PRIORITY_2_WEIGHT
#define PRIORITY_2_WEIGHT (6)   // 1.5x than PRIORITY_3_WEIGHT
#define PRIORITY_3_WEIGHT (4)

#define MILLISECOND_IN_USEC (1000)
#define SECOND_IN_USEC (1000000)
#define CLOCK_TICK_IN_USEC (100 * MILLISECOND_IN_USEC)

#define INIT_PROCESS_NAME "init"
#define DEFAULT_PROCESS_NAME "(unknown)"

#define PROCESS_CONTROL_MODULE_NAME "PROCESS_CONTROL"

typedef enum schedule_priority {
  PRIORITY_1,     // 0
  PRIORITY_2,     // 1
  PRIORITY_3,     // 2
  PRIORITY_COUNT  // 3
} schedule_priority;

typedef enum process_state {
  PROCESS_STATE_READY     = 1,   // runnable (running or in ready-queue)
  PROCESS_STATE_STOPPED   = 2,   // stopped by P_SIGSTOP
  PROCESS_STATE_BLOCKED   = 3,   // sleeping or waiting
  PROCESS_STATE_ZOMBIED   = 4,   // finished but not yet reaped
  PROCESS_STATE_TERMINATED= 5,   // fully cleaned-up (never scheduled)
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
  signalset_t pending_signals;
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
static bool kernel_started = false;

static pid_t shell_pid = -1; /* set in create_init() */

// the flag to indicate that the scheduler should be shut down
static bool shutdown;
// the mutex to protect shutdown
static pthread_mutex_t shutdown_mtx;

// maintain the clock tick value
static clock_tick_t clock_tick;

// flag of async SIGINT (Ctrl-C) being hit during this quantum
static sig_atomic_t flag_sigint;

// flag of async SIGTSTP (CTRL-Z) being hit during this quantum
static sig_atomic_t flag_sigtstp;

// the pid handed out most recently
static pid_t last_pid;

// pid of the process holding terminal control
static pid_t term_ctrl_pid;

// pcb pointer to the process currently running (or, during scheduling, the process running 
// in the last quantum). May be set to null during some part of the scheduling (quantum gap).
static pcb_t* running_prc;

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
static void register_async_signals();
static void handle_pending_signals();
static void examine_blocked_processes();

static void* init_routine(void* arg);

static pcb_t* get_pcb_at_pid(pid_t pid);
static void set_pcb_at_pid(pid_t pid, pcb_t* pcb_ptr);
static pid_t get_new_pid();
static pcb_t* create_pcb(pid_t pid, pcb_t* parent);
static void clean_up_pcb(void* pcb_void_ptr);
static pcb_t* get_pcb_by_spthread (spthread_t spthread);
static int set_routine_and_run_helper(pcb_t* proc, void* (*func)(void*), void* arg, bool wrap_exit);
static bool check_blocked_waiting_child(pcb_t* pcb);
static schedule_priority scheduler_get_next_priority();
static void set_process_name(pcb_t* pcb, const char* process_name);
static void process_deathbed(pcb_t* proc);

static void init_adopt_children(pcb_t* pcb);
static void register_blocked_state(pcb_t* pcb);

static void schedule_event_log(pcb_t *p, schedule_priority q);
static void lifecycle_event_log(pcb_t *p, const char *event, const char *extra);
static void nice_event_log(pcb_t *p, int old_pri, int new_pri);
static void block_event_log(pcb_t *p, const char *event);
static void stopcont_event_log(pcb_t *p, const char *event);

static bool remove_pcb_first_from_vec(pcb_t* pcb_ptr, Vec* vec);
static int remove_pcb_all_from_vec(pcb_t* pcb_ptr, Vec* vec);
static bool vec_contains_ptr(Vec *v, void *ptr);

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

static void async_sig_handler(int signum) {
  if (signum == SIGINT) {
    flag_sigint = true;
  }

  if (signum == SIGTSTP) {
    flag_sigtstp = true;
  }
}

/********************
 * internal functions *
 ********************/
int pcb_fd_alloc(pcb_t *p, proc_fd_entry_t *ent)
{
    if (!p || !ent) { errno = EBADF; return -1; }

    int ufd = 3;          /* 0,1,2 are stdin/out/err */
    for (; ufd < (int)vec_len(&p->fds); ++ufd)
        if (vec_get(&p->fds, ufd) == NULL) break;

    vec_set_force(&p->fds, ufd, ent);
    return ufd;                               /* new user-FD */
}

int pcb_fd_get(pcb_t *p, int ufd, proc_fd_entry_t **out)
{
    if (!p || ufd < 0 || (size_t)ufd >= vec_len(&p->fds)) {
        errno = EBADF;  return -1;
    }
    *out = vec_get(&p->fds, ufd);
    if (!*out) { errno = EBADF; return -1; }
    return 0;
}

void pcb_fd_close(pcb_t *p, int ufd)
{
    proc_fd_entry_t *tmp;
    if (pcb_fd_get(p, ufd, &tmp) == -1) return;   /* nothing to do */

    free(tmp);                                    /* release entry  */
    vec_set_force(&p->fds, ufd, NULL);            /* make a hole    */
}

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

    /* mask while sleeping –
   * allow the timer *and* keyboard signals so they wake sigsuspend()   */
  sigset_t suspend_set;
  sigfillset(&suspend_set);
  sigdelset(&suspend_set, SIGALRM);
  sigdelset(&suspend_set, SIGALRM);
sigdelset(&suspend_set, SIGINT);
sigdelset(&suspend_set, SIGTSTP);

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

      running_prc = (pcb_t*) vec_get(&ready_prcs_queues[next_priority], 0);
      vec_erase(&ready_prcs_queues[next_priority], 0);
      if (!running_prc) {
        logger_log(logger, LOG_LEVEL_ERROR, "PCB null found in ready queue[%d] in kernel_scheduler", next_priority);
        continue;
      }

      logger_log(logger, LOG_LEVEL_INFO, "PID[%d] popped from ready queue[%d], picked to run by scheduler",
        running_prc->pid, next_priority);
      schedule_event_log(running_prc, next_priority);

      spthread_continue(running_prc->spthread);
      sigsuspend(&suspend_set);
      ++clock_tick;
      spthread_suspend(running_prc->spthread);

      logger_log(logger, LOG_LEVEL_INFO, "Time quantum end for PID [%d]",
        running_prc->pid);

      // register async keyboard signals
      register_async_signals();
      // handle signals received during this quantum
      handle_pending_signals();

      // re-adding ready process to the back of the queue
      // note that this have to be done before examine_blocked_processes() (unblocking processes) to handle
      // the edge case where the last running process become blocked and then unblocked (e.g. k_sleep() for 
      // 1 clock tick), though this can also be fixed by explicitly checking for running_prc during
      //  examine_blocked_processes()
      if (running_prc->state == PROCESS_STATE_READY) {
        if (!vec_contains_ptr(&ready_prcs_queues[running_prc->priority], running_prc)) {
          vec_push_back(&ready_prcs_queues[running_prc->priority], running_prc);
        }
        
        logger_log(logger, LOG_LEVEL_INFO, "PID [%d] used quantum and re-added to ready queue[%d] in scheduler",
          running_prc->pid, running_prc->priority);
      }
      running_prc = NULL;

      // examine blocked processes and put back into ready queue those unblocked 
      // (sleep expires or waitpid got waited child)
      examine_blocked_processes();

      next_priority = scheduler_get_next_priority();

    } else if (vec_len(&ready_prcs_queues[PRIORITY_1]) == 0 && vec_len(&ready_prcs_queues[PRIORITY_2]) == 0
          && vec_len(&ready_prcs_queues[PRIORITY_3]) == 0) {
      // all ready queue is empty
      logger_log(logger, LOG_LEVEL_DEBUG, "All ready queues empty!", next_priority);
      sigsuspend(&suspend_set);
      ++clock_tick;

      // register async keyboard signals
      register_async_signals();
      // handle signals received during this quantum
      handle_pending_signals();
      // examine blocked processes and put back into ready queue those unblocked 
      // (sleep expires or waitpid got waited child)
      examine_blocked_processes();

    } else {
      logger_log(logger, LOG_LEVEL_DEBUG, "ready queue[%d] empty so pass", next_priority);
      next_priority = scheduler_get_next_priority();
    }
        /* re-acquire the mutex so the next while-condition is
     * synchronised with k_shutdown()                                  */
    assert_non_negative(pthread_mutex_lock(&shutdown_mtx),
                        "kernel_scheduler lock (bottom-of-loop)");

  }

  /* drop the lock we still hold when we break out of the loop */
  assert_non_negative(pthread_mutex_unlock(&shutdown_mtx),
                    "kernel_scheduler final unlock");
  logger_log(logger, LOG_LEVEL_DEBUG, "kernel_scheduler concludes");
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

  flag_sigint = false;
  flag_sigtstp = false;
  term_ctrl_pid = 0;

   struct sigaction act = (struct sigaction){
        .sa_handler = async_sig_handler,
        .sa_flags   = 0,               /* let syscalls be interrupted      */
      };
  sigaction(SIGINT, &act, NULL);
  sigaction(SIGTSTP, &act, NULL);

  // initialize the process lists
  // pcb will be cleaned up only when removing a process from all_prcs
  // others will not
  running_prc = NULL;
  all_prcs = vec_new(0, clean_up_pcb);
  blocked_prcs = vec_new(0, NULL);
  pending_sig_prcs = vec_new(0, NULL);

  for (schedule_priority i = PRIORITY_1; i < PRIORITY_COUNT; ++i) {
    ready_prcs_queues[i] = vec_new(0, NULL);
  }

  /* ───────── default logger ───────────────────────────────────────── */
if (!logger) {
  /* write to  logs/kernel.log  at INFO level                       */
  logger = logger_init("kernel", LOG_LEVEL_INFO);
}
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

  pcb_ptr->priority = PRIORITY_1;

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
static void* init_routine(void* arg)
{
    logger_log(logger, LOG_LEVEL_DEBUG, "INIT routine started");

    assert_non_null(arg, "Arg null for init_routine");


    starting_shell_args_t* args_to_init = (starting_shell_args_t*)arg;

    /* ───── create the shell process ─────────────────────────────── */
    pcb_t* starting_shell_pcb =
        create_pcb(get_new_pid(),           /* get a fresh PID       */
                   args_to_init->init_pcb); /* parent = INIT         */

                   
    assert_non_null(starting_shell_pcb,
                    "Created shell PCB is null in init_routine");

                   

    /* top priority for the interactive shell                        */
    starting_shell_pcb->priority = PRIORITY_1;

    const pid_t starting_shell_pid = starting_shell_pcb->pid;
    shell_pid = starting_shell_pid;        /* for SIGINT special-case */

    set_pcb_at_pid(starting_shell_pid, starting_shell_pcb);
    /* leave the exit-wrapper in place so PCB bookkeeping happens */

 
    set_routine_and_run_helper(starting_shell_pcb,
                                 args_to_init->shell_func,
                                 args_to_init->shell_arg,
                                 true  /* wrap_exit */);

                                 

    free(arg);


    /* give the shell terminal control */
    term_ctrl_pid = starting_shell_pid;

        /* give the shell its final, lower-case command name                */
    if (strcmp(starting_shell_pcb->process_name, DEFAULT_PROCESS_NAME) == 0)
        set_process_name(starting_shell_pcb, "shell");

    /* ───── wait until the shell terminates ──────────────────────── */
    /* Block until *any* child changes state – this puts INIT into
       PROCESS_STATE_BLOCKED and keeps it there most of the time.   */
    int st;
    while (true) {
        pid_t waited = k_waitpid(-1, &st, false);   /* NOHANG = false → block */

        if (waited == starting_shell_pid &&
            (P_WIFEXITED(st) || P_WIFSIGNALED(st)))
            break;                         /* shell ended */
        /* otherwise loop to wait for next change */
    }

    logger_log(logger, LOG_LEVEL_DEBUG, "INIT triggering shutdown");
    k_shutdown();

    /* mark our own PCB as ZOMBIED and leave the scheduler a corpse to reap */
    k_exit();                                     /* never returns */
    return NULL;                                  /* placate -Werror */
}



/**
 * Clean up the process control module metadata upon graceful shutdown
 */
// static void process_control_cleanup() {
  static void process_control_cleanup(void)
  {
      logger_log(logger, LOG_LEVEL_DEBUG, "cleanup started");
  

      spthread_t self;
      bool am_sp = spthread_self(&self);

  
      for (size_t i = 0; i < vec_len(&all_prcs); ++i) {
          pcb_t *p = vec_get(&all_prcs, i);
          if (!p) continue;
          if (am_sp && spthread_equal(self, p->spthread)) continue;
          spthread_cancel_and_join(p->spthread);
      }
  
  
      vec_destroy(&blocked_prcs);
  
      vec_destroy(&pending_sig_prcs);
  
      for (schedule_priority i = PRIORITY_1; i < PRIORITY_COUNT; ++i) {
          vec_destroy(&ready_prcs_queues[i]);
        
      }
  
      vec_destroy(&all_prcs);
      
  
      pthread_mutex_destroy(&shutdown_mtx);
      
  
      logger_close(logger);
      
  }
  

/**
 * Register the keyboard async signals (CTRL-C, CTRL-Z) to the process holding terminal control
 */
static void register_async_signals() {
  if (!flag_sigint && !flag_sigtstp) {
    return;
  }

  /* never forward to init itself, but *always* forward to whoever      *
 * currently owns the terminal – including the shell                  */
if (term_ctrl_pid != INIT_PID) {
  pcb_t *p = get_pcb_at_pid(term_ctrl_pid);
  if (p) {
      if (flag_sigint)
      p->pending_signals = P_SIG_ADDSIG(p->pending_signals, P_SIGINT);
      if (flag_sigtstp)
          p->pending_signals = P_SIG_ADDSIG(p->pending_signals, P_SIGSTOP);
        
        if (!vec_contains_ptr(&pending_sig_prcs, p))
           vec_push_back(&pending_sig_prcs, p);
  }
}

  flag_sigint = false;
  flag_sigtstp = false;
}

/**
 * Handle the pending signals during the quantum gap
 */
static void handle_pending_signals() {
  for (size_t i = 0; i < vec_len(&pending_sig_prcs); ++i) {
    pcb_t* proc = vec_get(&pending_sig_prcs, i);
    if (!proc) {
      logger_log(logger, LOG_LEVEL_WARN, "Null PCB found in pending_sig_prcs in handle_pending_signals");
      continue;
    }

    signalset_t sigset = proc->pending_signals;

    if (P_SIG_HASSIG(sigset, P_SIGTERM)) {
      logger_log(logger, LOG_LEVEL_DEBUG, "Process P_SIGTERM for PID[%d]", proc->pid);

      // process will be killed by signal, other signals will be ignored

      if (proc->state == PROCESS_STATE_TERMINATED) {
        proc->pending_signals = 0;
        continue;
      }

      proc->waitpid_stat = P_SIGTERM;
      lifecycle_event_log(proc, "SIGNALED", NULL);

      // remove from ready queues and blocking list if necessary
      if (proc->state == PROCESS_STATE_READY) {
        if (remove_pcb_first_from_vec(proc, &ready_prcs_queues[proc->priority])) {
          logger_log(logger, LOG_LEVEL_DEBUG, "PID[%d] removed from ready queue %d in handle_pending_signals", proc->pid, proc->priority);
        } else {
          logger_log(logger, LOG_LEVEL_DEBUG, "PID[%d] not found in ready queue %d in handle_pending_signals", proc->pid, proc->priority);
        } 
      } else if (proc->state == PROCESS_STATE_BLOCKED) {
        if (remove_pcb_first_from_vec(proc, &blocked_prcs)) {
          logger_log(logger, LOG_LEVEL_DEBUG, "PID[%d] removed from blocked list in handle_pending_signals", proc->pid);
        } else {
          logger_log(logger, LOG_LEVEL_DEBUG, "PID[%d] not found in blocked list in handle_pending_signals", proc->pid);
        } 
      }

      // cancel pthread
      spthread_t spthd = proc->spthread;
      spthread_cancel(spthd);
      spthread_continue(spthd);
      spthread_suspend(spthd); // forces the spthread to hit a cancellation point

      // register waitable for parent and trigger orphan adoption
      process_deathbed(proc);

      proc->state = PROCESS_STATE_TERMINATED;
      proc->pending_signals = 0;

      // other signals will be ignored
      continue;
    }

        /* ---------- Ctrl-C (interrupt) ---------- */
    if (P_SIG_HASSIG(sigset, P_SIGINT)) {
        /* 1.  If the shell itself is in the foreground, ignore the SIGINT
         *     (just wakes its read() so it prints a new prompt).          */
                if (proc->pid == shell_pid) {
                      proc->pending_signals = P_SIG_DELSIG(proc->pending_signals,
                                                           P_SIGINT);
                      goto next_proc;                 /* <<<  skip bookkeeping     */
                  }
        /* 2.  Any *other* foreground job: translate to SIGTERM, then let
         *     the existing SIGTERM handler below do the heavy lifting.   */
        proc->pending_signals =
            P_SIG_DELSIG(proc->pending_signals, P_SIGINT);
        proc->pending_signals =
            P_SIG_ADDSIG(proc->pending_signals, P_SIGTERM);
        sigset = proc->pending_signals;     /* update local copy          */
      }

          /* ---------- Ctrl-Z (interactive shell ignores) ---------- */
    if (proc->pid == shell_pid && P_SIG_HASSIG(sigset, P_SIGSTOP)) {
          /* Wake its read() (EINTR) but do NOT change its state */
          proc->pending_signals =
                  P_SIG_DELSIG(proc->pending_signals, P_SIGSTOP);
          goto next_proc;          /* skip the normal STOP bookkeeping */
      }

    // note: if both P_SIGSTOP and P_SIGCONT are received, P_SIGSTOP will prevail (as Linux does)
    if (P_SIG_HASSIG(sigset, P_SIGSTOP)) {
      logger_log(logger, LOG_LEVEL_DEBUG, "Process P_SIGSTOP for PID[%d]", proc->pid);

      if (proc->state == PROCESS_STATE_TERMINATED || proc->state == PROCESS_STATE_STOPPED) {
        proc->pending_signals = 0;
        continue;
      }

      // remove from ready queues if necessary
      if (proc->state == PROCESS_STATE_READY) {
        if (remove_pcb_first_from_vec(proc, &ready_prcs_queues[proc->priority])) {
          logger_log(logger, LOG_LEVEL_DEBUG, "PID[%d] removed from ready queue %d in handle_pending_signals", proc->pid, proc->priority);
        } else {
          logger_log(logger, LOG_LEVEL_DEBUG, "PID[%d] not found in ready queue %d in handle_pending_signals", proc->pid, proc->priority);
        } 
      }
      // blocked list do not need to be checked as a process stays in the blocked list if both blocked and stopped

      proc->waitpid_stat = P_SIGSTOP;

      proc->state = PROCESS_STATE_STOPPED;
      stopcont_event_log(proc, "STOPPED");   // blocked process will also be marked stopped
      proc->pending_signals = 0;

      // P_SIGCONT will be ignored
      continue;
    }

    if (P_SIG_HASSIG(sigset, P_SIGCONT)) {
      logger_log(logger, LOG_LEVEL_DEBUG, "Process P_SIGCONT for PID[%d]", proc->pid);

      if (proc->state == PROCESS_STATE_STOPPED) {

        if (proc->blocked_by_sleep || proc->waiting_child_pid != 0) {
          // process is also blocked
          proc->state = PROCESS_STATE_BLOCKED;

        } else {
          // not blocked, put back to ready queue
          proc->state = PROCESS_STATE_READY;
          if (proc != running_prc) {
            // put into ready queue only if it is not running_prc, to avoid double-queuing 
            // (running_prc will be added back to ready queue by scheduler after quantum finishes
            // if its state is READY)

            if (!vec_contains_ptr(&ready_prcs_queues[proc->priority], proc)) {
              vec_push_back(&ready_prcs_queues[proc->priority], proc);
            }

            stopcont_event_log(proc, "CONTINUED");
          }
        }

      }
    }

        /* notify the parent only for state–changing signals             */
    if ((P_SIG_HASSIG(sigset, P_SIGTERM) ||
         P_SIG_HASSIG(sigset, P_SIGSTOP) ||
         P_SIG_HASSIG(sigset, P_SIGCONT)) &&
        proc->parent) {
        vec_push_back(&proc->parent->waitable_children, proc);
    }
    proc->pending_signals = 0;
    next_proc: ;
  }

  vec_clear(&pending_sig_prcs);
}

static bool looks_like_cstring(const char *s)
{
    if (!s) return false;

    /* accept up to 64 printable ASCII chars followed by NUL        */
   for (size_t i = 0; i < 64; ++i) {
       unsigned char c = (unsigned char)s[i];
        if (c == '\0')              /* NUL terminator – good        */
            return i > 0;           /* empty string is “bad”        */
        if (c < 32 || c > 126)      /* not printable ASCII          */
            return false;
    }
    return false;                   /* too long / no NUL            */
}
/**
 * Examine the current blocked processes and unblock those with block condition not longer holds
 * 
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
    block_event_log(proc, "UNBLOCKED");
    vec_erase(&blocked_prcs, index);

    // schedule for running only if it is showing as BLOCKED previously
    // should not do so for STOPPED as they should continue to be STOPPED even when
    // the blocking condition is lifted
    if (proc->state == PROCESS_STATE_BLOCKED) {
      proc->state = PROCESS_STATE_READY;
      if (proc != running_prc) {
        // put into ready queue only if it is not running_prc, to avoid double-queuing 
        // (running_prc will be added back to ready queue by scheduler after quantum finishes
        // if its state is READY)
        if (!vec_contains_ptr(&ready_prcs_queues[proc->priority], proc)) {
          vec_push_back(&ready_prcs_queues[proc->priority], proc);
        }
        
        logger_log(logger, LOG_LEVEL_INFO, "PID[%d] unblocks and ready for schedule (put into ready queue[%d])", proc->pid, proc->priority);
      }
    } else {
      logger_log(logger, LOG_LEVEL_INFO, "PID[%d] unblocks but not ready for schedule (still stopped)", proc->pid);
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
    .fds = vec_new(0, free),
    .pending_signals = 0,
    .process_name = NULL
  };

  if (parent) {
        pcb_ptr->parent = parent;
    vec_push_back(&(parent->children), pcb_ptr);

    /* ── duplicate the parent’s open FDs so child has *independent*
     *    kernel descriptors and its *own* offsets                 */
    for (size_t i = 0; i < vec_len(&parent->fds); ++i) {
        proc_fd_entry_t *p_ent = vec_get(&parent->fds, i);
        if (!p_ent) {                   /* hole → leave hole         */
            vec_push_back(&pcb_ptr->fds, NULL);
            continue;
        }
        /* dup the kernel-fd so offsets are separate                */
        int new_kfd = k_lseek(p_ent->kfd, 0, F_SEEK_CUR);
        /* using k_open again would need the path – dup is easier   */
        /* simple dup: allocate another entry in g_fd_table         */
        new_kfd = k_open(NULL /* dup */, 0); /* ⇐ add tiny k_dup later */
        /* FALL-BACK until k_dup() exists: reopen with same mode    */
        if (new_kfd < 0) continue;      /* out of descriptors – ignore */

        proc_fd_entry_t *child_ent = malloc(sizeof *child_ent);
        child_ent->kfd = new_kfd;
        vec_push_back(&pcb_ptr->fds, child_ent);
    }
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
static int set_routine_and_run_helper(pcb_t* proc, void* (*func)(void*), void* arg, bool wrap_exit) {
  if (!proc) {
    logger_log(logger, LOG_LEVEL_ERROR, "pcb ptr is NULL for k_set_routine_and_run");
    return -2;
  }

  if (!func) {
    logger_log(logger, LOG_LEVEL_ERROR, "func is NULL for k_set_routine_and_run");
    return -2;
  }

  // CREATE SPTHREAD
  int create_status;

  if (wrap_exit) {
    routine_exit_wrapper_args_t* wrapped_args = wrap_routine_exit_args(func, arg);
    create_status = spthread_create(&(proc->spthread), NULL, routine_exit_wrapper_func, wrapped_args);
  } else {
    create_status = spthread_create(&(proc->spthread), NULL, func, arg);
  }

  if (create_status < 0) {
    logger_log(logger, LOG_LEVEL_ERROR, "Spthread creation error for PID[%d]", proc->pid);
    proc->state = PROCESS_STATE_TERMINATED;
    return -1;
  }
  logger_log(logger, LOG_LEVEL_DEBUG, "Spthread created with thd routine for PID[%d]", proc->pid);

  /* ---------------------------------------------------------------
   * Decide a human-readable command name BEFORE logging “CREATE”.
   *  •  INIT                         →  "INIT"
   *  •  regular spawn(argv)         →  argv[0]
   *  •  spawn_wrapper_arg.real_arg  →  real_arg[0]
   *  •  fallback                    →  "(unknown)"
   * --------------------------------------------------------------*/

  const char *process_name = DEFAULT_PROCESS_NAME;

  if (proc->pid == INIT_PID) {
      process_name = INIT_PROCESS_NAME;

  /* case 1: ordinary wrap_exit where arg is **argv                     */
  } else if (wrap_exit && arg &&
             looks_like_cstring(((char **)arg)[0])) {
      process_name = ((char **)arg)[0];

  /* case 2: s_spawn() →  spawn_wrapper_arg                            */
  } else if (func == spawn_entry_wrapper && arg) {
    struct spawn_wrapper_arg *sw = (struct spawn_wrapper_arg *)arg;
      char **maybe_argv = (char **)sw->real_arg;
      if (maybe_argv && looks_like_cstring(maybe_argv[0]))
          process_name = maybe_argv[0];
  }
set_process_name(proc, process_name);

  logger_log(logger, LOG_LEVEL_DEBUG, "Process name set for PID[%d]: %s", proc->pid, proc->process_name);

  // ADD TO SCHEDULING READY QUEUE
  proc->state = PROCESS_STATE_READY;

  if (!vec_contains_ptr(&ready_prcs_queues[proc->priority], proc)) {
    vec_push_back(&ready_prcs_queues[proc->priority], proc);
  }
  
  logger_log(logger, LOG_LEVEL_DEBUG, "PID [%d] added to ready queue[%d] in set_routine_and_run_helper", proc->pid, proc->priority);

  lifecycle_event_log(proc, "CREATED", NULL);

  return 0;
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

      /* If pcb **is already** INIT, there is nobody to adopt from.       */
    pcb_t *init_pcb = get_pcb_at_pid(INIT_PID);
    if (pcb == init_pcb)
        return;

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
      /* only insert once */
      if (!vec_contains_ptr(&blocked_prcs, pcb))
      vec_push_back(&blocked_prcs, pcb);

  if (pcb->state == PROCESS_STATE_READY) {
      pcb->state = PROCESS_STATE_BLOCKED;
      block_event_log(pcb, "BLOCKED");
  }
  /* if it was STOPPED or already BLOCKED we leave the state unchanged */

  // no need to change state if was STOPPED or BLOCKED
  // since a stopped process should still be stopped when blocked or unblocked
  // waiting_child_pid and blocked_by_sleep will indicate whether the process should be BLOCKED
  // or READY when the stop condition is lifted (i.e. receives P_SIGCONT)
}

/* Cancel a spthread, let it reach a cancellation point, then join it */
static void spthread_cancel_and_join(spthread_t t)
{
    /* pthread_t is opaque; cast to void * for %p */

    spthread_cancel(t);          /* set the cancellation flag            */
    spthread_continue(t);        /* make sure it is running              */
    spthread_suspend(t);         /* … and block until it hits a checkpoint */

    spthread_join(t, NULL);      /* reap resources                       */

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
 * For a process that is about to die, handle its children and register waitable status to its parent
 * May be called by k_exit() or handle_pending_signals()
 */
static void process_deathbed(pcb_t* proc) {
  if (!proc) {
    return;
  }

  // add self to parent's waitable children
  if (proc->parent) {
    vec_push_back(&(proc->parent->waitable_children), proc);
  }

      /* from here on a second invocation can safely bail out            */
    if (proc->state == PROCESS_STATE_ZOMBIED ||
          proc->state == PROCESS_STATE_TERMINATED)
          return;

    /* give the terminal back to INIT itself                     */
  if (term_ctrl_pid == proc->pid)
      term_ctrl_pid = INIT_PID;

  proc->state = PROCESS_STATE_ZOMBIED;
  lifecycle_event_log(proc, "ZOMBIE", NULL);

  // have INIT adopt all children (and waitable children)
  logger_log(logger, LOG_LEVEL_DEBUG,
    "Triggering INIT adoption for PID[%d] (%zu children, %zu waitable_children)",
    proc->pid, vec_len(&proc->children), vec_len(&proc->waitable_children));
  // init_adopt_children(proc);

}

/**
 * Helper function to print log the schedule events
 */
static void schedule_event_log(pcb_t *p, schedule_priority q)
{
    if (!p) return;

    /* keep the line format identical – just lower the level            */
    logger_log(logger, LOG_LEVEL_INFO,
               "[%d]\tSCHEDULE\t%d\t%d\t%s",
               clock_tick,
              p->pid,
               q,
               (p->process_name) ? p->process_name : "<null>");
 }

/**
 * Helper function to print log the life cycle events
 */
static void lifecycle_event_log(pcb_t *p,
  const char *event,
  const char *extra)
/* event = CREATE | SIGNALED | EXITED | ZOMBIE | ORPHAN | WAITED    */
{
if (!p || !event) return;

/* [ticks] EVENT PID NICE_VALUE PROCESS_NAME [extra] */
logger_log(logger, LOG_LEVEL_INFO, // instead of LOG_LEVEL_INFO
"[%d]\t%s\t%d\t%d\t%s%s%s",
clock_tick,
event,
p->pid,
p->priority,
(p->process_name) ? p->process_name : "<null>",
(extra) ? "\t" : "",
(extra) ? extra : "");
}

static void nice_event_log(pcb_t *p, int old_pri, int new_pri)
/* [ticks] NICE PID OLD_NICE_VALUE NEW_NICE_VALUE PROCESS_NAME      */
{
    if (!p) return;

    logger_log(logger, LOG_LEVEL_INFO,
               "[%d]\tNICE\t%d\t%d\t%d\t%s",
               clock_tick,
               p->pid,
               old_pri,
               new_pri,
               (p->process_name) ? p->process_name : "<null>");
}

static void block_event_log(pcb_t *p, const char *event)
{
    if (!p || !event) return;
    logger_log(logger, LOG_LEVEL_INFO,
               "[%d]\t%s\t%d\t%d\t%s",
               clock_tick,
               event,
               p->pid,
               p->priority,
               (p->process_name) ? p->process_name : "<null>");
}

static void stopcont_event_log(pcb_t *p, const char *event)
{
    block_event_log(p, event);            /* same DEBUG level */
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

/* === util for pointer-membership in a Vec ======================= */
static bool vec_contains_ptr(Vec *v, void *ptr)
{
    for (size_t i = 0; i < vec_len(v); ++i)
        if (vec_get(v, i) == ptr)
            return true;
    return false;
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

int k_set_routine_and_run(pcb_t* proc, void* (*func)(void*), void* arg) {
  return set_routine_and_run_helper(proc, func, arg, true);
}

void k_proc_cleanup(pcb_t* proc) {
  if (proc->state != PROCESS_STATE_ZOMBIED && proc->state != PROCESS_STATE_TERMINATED) {
    logger_log(logger, LOG_LEVEL_WARN, "k_proc_cleanup not done as process not terminated");
    return;
  }

  /* join only once, ignore if already joined */
  spthread_cancel_and_join(proc->spthread);
  proc->state = PROCESS_STATE_TERMINATED;

  pcb_t* parent_pcb = proc->parent;
  if (parent_pcb) {
    
    // remove from parent's child vec
    // assume waitable children has been cleaned up when it becomes zombie
    if (!remove_pcb_first_from_vec(proc, &parent_pcb->children)) {
      logger_log(logger, LOG_LEVEL_WARN, "Cannot find reaped child in k_waitpid");
      
    }
  } else {
    logger_log(logger, LOG_LEVEL_WARN, "Parent PCB null in k_proc_cleanup");
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
  if (pid < -1 || pid == 0) {
    // TODO: set errno
    return -1;
  }

  pcb_t* child_pcb = NULL;      // pcb null indicates wait for any child in this function
  pcb_t* self_pcb = k_get_self_pcb();

  if (vec_len(&self_pcb->children) == 0) {
    errno = ECHILD;            /* POSIX semantics            */
    return -1;
}

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

      init_adopt_children(waited_child);

      if (waited_child->state == PROCESS_STATE_ZOMBIED || waited_child->state == PROCESS_STATE_TERMINATED) {
             k_proc_cleanup(waited_child);
             }

      return waited_child_pid;

    } else {
      // have not found a child to wait, register block info and block, or return 0 for nohang
      if (nohang) {
        /* if the caller has *no* children at all, report ECHILD     */
    if (vec_len(&self_pcb->children) == 0) {
      errno = ECHILD;
      return -1;
  }
  /* otherwise: children exist but none is waitable right now  */
  return 0;
      }

      logger_log(logger, LOG_LEVEL_DEBUG, "PID[%d] cannot find waited child, will start blocking", self_pcb->pid);
      self_pcb->waiting_child_pid = pid;
      register_blocked_state(self_pcb);

      assert_non_negative(spthread_suspend_self(), "spthread_suspend_self error in k_waitpid");
    }
  }
}

int k_nice(pid_t pid, int priority) {
  if (priority >= PRIORITY_COUNT) {
    // TODO: set errno?
    return -1;
  }

  pcb_t* proc = get_pcb_at_pid(pid);
  if (!proc) {
    // TODO: set errno?
    return -1;
  }

  if (remove_pcb_first_from_vec(proc, &ready_prcs_queues[proc->priority])) {
    if (proc != running_prc) {
      logger_log(logger, LOG_LEVEL_DEBUG, "PID[%d] removed from ready queue[%d] in k_nice", proc->pid, proc->priority);
    } else {
      // for debugging, should theoretically not happen
      logger_log(logger, LOG_LEVEL_WARN, "PID[%d] removed from ready queue[%d] (exist unexpectedly as running_prc) in k_nice", proc->pid, proc->priority);
    }
  } else {
    // for debugging, should theoretically not happen
    if (proc != running_prc) {
      logger_log(logger, LOG_LEVEL_WARN, "PID[%d] not found unexpectedly in ready queue[%d] in k_nice", proc->pid, proc->priority);
    }
  }

    int old_pri = proc->priority;
  proc->priority = priority;
  nice_event_log(proc, old_pri, priority);
  
  if (!vec_contains_ptr(&ready_prcs_queues[proc->priority], proc)) {
    vec_push_back(&ready_prcs_queues[proc->priority], proc);
  }
  
  logger_log(logger, LOG_LEVEL_DEBUG, "PID[%d] added to ready queue[%d] in k_nice", proc->pid, proc->priority);

  return 0;

}

int k_kill(pid_t pid, int signal) {
  if (pid <= 0) {
    // TODO: set errno    invalid argument / PID does not exist
    return -1;
  }

  // do not allow sending signal to INIT
  if (pid == INIT_PID) {
    // TODO: set errno    no permission
    return -1;
  }

  pcb_t* proc = get_pcb_at_pid(pid);
  if (!proc) {
    // TODO: set errno    PID does not exist
    return -1;
  }

  // ignore signals sent to zombie processes but normal return
  if (proc->state == PROCESS_STATE_TERMINATED) {
    return 0;
  }

  // register pending sigset in pcb
  proc->pending_signals = P_SIG_ADDSIG(proc->pending_signals, signal);

  // record the process which has pending signal
  if (!vec_contains_ptr(&pending_sig_prcs, proc)) 
  vec_push_back(&pending_sig_prcs, proc);

  return 0;
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

    /* record normal exit status and mark zombie */
  self_pcb->waitpid_stat = 0;                    /* WIFEXITED */
  lifecycle_event_log(self_pcb, "EXITED", NULL);

  process_deathbed(self_pcb);                   /* sets ZOMBIED */
  
  spthread_exit(NULL);
}

void k_shutdown(void) {
  assert_non_negative(spthread_disable_interrupts_self(), "Error disable_interrupt in k_shutdown");
  assert_non_negative(pthread_mutex_lock(&shutdown_mtx), "Mutex lock error in k_shutdown");
  shutdown = true;

  assert_non_negative(pthread_mutex_unlock(&shutdown_mtx), "Mutex unlock error in k_shutdown");
  assert_non_negative(spthread_enable_interrupts_self(), "Error enable_interrupts in k_shutdown");
}

int k_tcsetpid(pid_t pid) {
  if (pid <= 0) {
    // TODO: errno
    return -1;
  }

  if (!get_pcb_at_pid(pid)) {
    // TODO: errno
    return -1;
  }

  term_ctrl_pid = pid;
  return 0;

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
              case PROCESS_STATE_ZOMBIED:
        stat = 'Z';
        break;
      case PROCESS_STATE_STOPPED:
        stat = 'S';
        break;
      case PROCESS_STATE_BLOCKED:
        stat = 'B';
        break;
      case PROCESS_STATE_TERMINATED:
      stat = 'T';            /* optional: “T” for fully-reaped        */
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

static inline int set_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

int k_pipe(int fds[2])
{
    if (pipe(fds) == -1)          /* ordinary POSIX pipe()              */
        return -1;

    /* mark both ends close-on-exec so children only inherit dup’ed FDs  */
    if (set_cloexec(fds[0]) == -1 || set_cloexec(fds[1]) == -1) {
        int save = errno;
        close(fds[0]); close(fds[1]);
        errno = save;
        return -1;
    }
    return 0;
}