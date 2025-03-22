#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

#include "./spthread.h"

#define NUM_THREADS 4
#define BUF_SIZE 4096

///////////////////////////////////////////////////////////////////////////////
// scheduler stuff
///////////////////////////////////////////////////////////////////////////////

static spthread_t threads[NUM_THREADS];
static const int centisecond = 10000;  // 10 milliseconds

static bool done = false;

// signal handler for sigalarm
// can be left empty since we just need
// to know that the handler has gone off and not
// terminate when we get the signal.
static void alarm_handler(int signum) {}

static void scheduler(void) {
  int curr_thread_num = 0;

  // mask for while scheduler is waiting for
  // alarm to go off
  sigset_t suspend_set;
  sigfillset(&suspend_set);
  sigdelset(&suspend_set, SIGALRM);

  // just to make sure that
  // sigalrm doesn't terminate the process
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
  it.it_interval = (struct timeval){.tv_usec = centisecond * 10};
  it.it_value = it.it_interval;
  setitimer(ITIMER_REAL, &it, NULL);

  // locks to check the global value done
  while (!done) {
    curr_thread_num = (curr_thread_num + 1) % NUM_THREADS;
    spthread_t curr_thread = threads[curr_thread_num];

    spthread_continue(curr_thread);
    sigsuspend(&suspend_set);
    spthread_suspend(curr_thread);
  }
}

///////////////////////////////////////////////////////////////////////////////
// thread funcs stuff
///////////////////////////////////////////////////////////////////////////////
static void* cat([[maybe_unused]] void* arg) {
  // arg is ignored, mark it that way so compiler stops complaining

  fputs("cat: started\n", stderr);
  char buffer[BUF_SIZE];

  while (true) {
    const ssize_t n = read(STDIN_FILENO, buffer, BUF_SIZE);
    if (n == 0) {  // Ctrl-D
      break;
    }

    if (n > 0) {
      write(STDOUT_FILENO, buffer, n);
    }
  }

  fputs("cat: returning\n", stderr);

  spthread_disable_interrupts_self();
  done = true;
  spthread_enable_interrupts_self();

  fputs("cat: actually returning\n", stderr);
  return NULL;
}

static void* inc(void* arg) {
  int thread_num = *(int*)arg;
  free(arg);
  for (int i = 0;; i++) {
    dprintf(STDERR_FILENO, "%*cThread %d: i = %d\n", thread_num * 20, ' ',
            thread_num, i);
    usleep(thread_num * centisecond);
  }
  return NULL;
}

void cancel_and_join(spthread_t thread) {
  spthread_cancel(thread);
  spthread_continue(thread);
  spthread_suspend(thread); // forces the spthread to hit a cancellation point
  fputs("waiting on a thread to exit.\n", stderr);
  spthread_join(thread, NULL);
}

int main(void) {
  spthread_t temp;

  // create the cat thread
  spthread_create(&temp, NULL, cat, NULL);
  threads[0] = temp;

  for (int i = 1; i < NUM_THREADS; i++) {
    int* arg = malloc(sizeof(int));
    *arg = i;
    spthread_create(&temp, NULL, inc, arg);
    threads[i] = temp;
  }

  // scheduler is not a separate thread
  scheduler();

  // cleanup
  for (int i = 0; i < NUM_THREADS; i++) {
    cancel_and_join(threads[i]);
  }
}
