#ifndef PENNOS_SIGNALS_H_
#define PENNOS_SIGNALS_H_

/* signals are represented by non-negative integer values in the system */

typedef int signalset_t;

typedef enum signal_value {
  P_SIGSTOP = 0,    // a thread receiving this signal should be stopped
  P_SIGCONT = 1,    // a thread receiving this signal should be continued
  P_SIGTERM = 2,    // a thread receiving this signal should be terminated

} signal_value;

#define P_SIG_FLAG(signo) (1 << (signo))
#define P_SIG_ADDSIG(sigset, signo) ((sigset) | P_SIG_FLAG(signo))
#define P_SIG_HASSIG(sigset, signo) (((sigset) & P_SIG_FLAG(signo)) != 0)

#define P_WIFEXITED(st)    ((st) == 0)            /* normal return / s_exit   */
#define P_WIFSTOPPED(st)   ((st) == P_SIGSTOP)    /* became stopped           */
#define P_WIFSIGNALED(st)  ((st) == P_SIGTERM)    /* killed by P_SIGTERM      */


#endif  // PENNOS_SIGNALS_H_