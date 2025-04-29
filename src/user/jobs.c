/* jobs.c – PennOS-friendly job tracking – no host wait/kill/sys/wait.h */
#include "jobs.h"
#include "../common/pennos_signals.h"     /* P_SIG* values                */
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include "../syscall/syscall_kernel.h"     /* s_spawn, s_kill, … */
#include <ctype.h>          /* ← for isspace() */

#define MAX_JOBS 64

/* we *can* run with no extra helper – the SIGCHLD handler below does
 * all the reaping.  Keep the variable so jobs_shutdown() can stay a
 * no-op if nothing was started.                                           */
static pid_t helper_pid = -1;

static job_t table[MAX_JOBS];
static int    next_jid = 1;
static int    fg_index = -1;      /* index of foreground job   */

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


/* ───────── public API ───────── */
void jobs_init(void)
{
    memset(table, 0, sizeof table);
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

       /* -----------------------------------------------------------
    * 1. take length up to buffer limit
    * 2. drop the final '\n' (entered by user <RET>)
    * 3. drop optional trailing " &" (space + ampersand)
    * --------------------------------------------------------- */
   size_t n = strnlen(cmdline, sizeof(table[idx].cmdline) - 1);

   /* step-2 : strip newline / trailing blanks ------------------ */
   while (n > 0 && isspace((unsigned char)cmdline[n-1]))
       --n;                         /* removes '\n' and spaces    */

   /* step-3 : strip “ &” --------------------------------------- */
   if (n >= 2 && cmdline[n-1] == '&' &&
       isspace((unsigned char)cmdline[n-2])) {
       n -= 2;                      /* drop & and the preceding space */
       /* strip any extra spaces that might precede it             */
       while (n > 0 && isspace((unsigned char)cmdline[n-1]))
           --n;
   }


   memcpy(table[idx].cmdline, cmdline, n);
   table[idx].cmdline[n] = '\0';

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

/* return the *latest* job whose state bit appears in wanted_mask
 * wanted_mask is a bitmap:  (1<<JOB_RUNNING) | (1<<JOB_STOPPED) | …   */
job_t *jobs_most_recent(int wanted_mask)
{
    for (int i = MAX_JOBS - 1; i >= 0; --i) {
        if (table[i].jid == 0)                /* unused slot         */
            continue;
        if (wanted_mask & (1 << table[i].state))
            return &table[i];
    }
    return NULL;
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
