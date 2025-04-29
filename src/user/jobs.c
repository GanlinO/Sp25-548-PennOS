/* jobs.c – PennOS-friendly job tracking – no host wait/kill/sys/wait.h */
#include "jobs.h"
#include "../common/pennos_signals.h"     /* P_SIG* values                */
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include "../syscall/syscall_kernel.h"     /* s_spawn, s_kill, … */

#define MAX_JOBS 64

/* we *can* run with no extra helper – the SIGCHLD handler below does
 * all the reaping.  Keep the variable so jobs_shutdown() can stay a
 * no-op if nothing was started.                                           */
static pid_t helper_pid = -1;

static job_t table[MAX_JOBS];
static int    next_jid = 1;
static int    fg_index = -1;              /* index of foreground job       */

/* ───────── helpers ───────── */
static int find_empty_slot(void)
{
    for (int i = 0; i < MAX_JOBS; ++i)
        if (table[i].jid == 0) return i;
    return -1;
}
static int index_by_pid(pid_t pid)
{
    for (int i = 0; i < MAX_JOBS; ++i)
        if (table[i].jid && table[i].pid == pid) return i;
    return -1;
}

/* ───────── SIGCHLD handler ───────── */
static void chld_handler(int _unused)
{
    /* iterate over **known** jobs only                                */
    for (int i = 0; i < MAX_JOBS; ++i) {
        if (table[i].jid == 0)               /* slot unused           */
            continue;

        int   status;
        pid_t pid = s_waitpid(table[i].pid, &status, true);  /* NOHANG */
        if (pid <= 0)                       /* nothing new            */
            continue;

        /* we reaped a background/-pipeline job                       */
        if      (P_WIFSTOPPED(status)) table[i].state = JOB_STOPPED;
        else if (status == P_SIGCONT)   table[i].state = JOB_RUNNING;
        else                            table[i].state = JOB_DONE;

        if (i == fg_index && table[i].state != JOB_RUNNING)
            fg_index = -1;
    }
}

/* ───────── public API ───────── */
void jobs_init(void)
{
    memset(table, 0, sizeof table);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = chld_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGCHLD, &sa, NULL);

    helper_pid = -1;
}

void jobs_shutdown(void)             /* <-- new */
{
    if (helper_pid > 0)
        s_kill(helper_pid, P_SIGTERM);   /* the worker simply returns   */
}

int jobs_add(pid_t pid, const char *cmdline, bool bg)
{
    int idx = find_empty_slot();
    if (idx < 0) return -1;

    table[idx].jid   = next_jid++;
    table[idx].pid   = pid;
    table[idx].state = JOB_RUNNING;
    strncpy(table[idx].cmdline, cmdline, sizeof(table[idx].cmdline) - 1);

    if (!bg) fg_index = idx;
    return table[idx].jid;
}

void jobs_update(pid_t pid, job_state_t st)
{
    int i = index_by_pid(pid);
    if (i >= 0) table[i].state = st;
}
void jobs_remove(pid_t pid)
{
    int i = index_by_pid(pid);
    if (i >= 0) memset(&table[i], 0, sizeof(job_t));
}

/* ───────── queries & printing ───────── */
job_t *jobs_by_jid(int jid)
{
    for (int i = 0; i < MAX_JOBS; ++i)
        if (table[i].jid == jid) return &table[i];
    return NULL;
}
job_t *jobs_current_fg(void)
{
    return (fg_index >= 0) ? &table[fg_index] : NULL;
}
bool jobs_have_stopped(void)
{
    for (int i = 0; i < MAX_JOBS; ++i)
        if (table[i].jid && table[i].state == JOB_STOPPED) return true;
    return false;
}
void jobs_list(void)
{
    for (int i = 0; i < MAX_JOBS; ++i) if (table[i].jid) {
        const char *st =
            (table[i].state == JOB_RUNNING) ? "Running" :
            (table[i].state == JOB_STOPPED) ? "Stopped" : "Done";
        fprintf(stderr, "[%d] %-7s  %s\n",
                table[i].jid, st, table[i].cmdline);
    }
}
