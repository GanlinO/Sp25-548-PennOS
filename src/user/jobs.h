/* jobs.h – job-table & bg/fg helpers – PennOS compliant */
#ifndef JOBS_H
#define JOBS_H

#include <stdbool.h>
#include <stdint.h>
#include "../syscall/syscall_kernel.h"   /* pid_t, s_* wrappers            */

typedef enum { JOB_RUNNING, JOB_STOPPED, JOB_DONE } job_state_t;

typedef struct {
    int        jid;                  /* job id shown to the user          */
    pid_t      pid;                  /* first pid (= pgrp leader)         */
    char       cmdline[128];         /* printable command line            */
    job_state_t state;
} job_t;

/* life-cycle ------------------------------------------------------------- */
void  jobs_init(void);                               /* call once          */
int   jobs_add(pid_t pid, const char *cmd, bool bg); /* returns jid        */
void  jobs_update(pid_t pid, job_state_t st);        /* helper if needed   */
void  jobs_remove(pid_t pid);

/* queries ---------------------------------------------------------------- */
job_t *jobs_by_jid(int jid);           /* NULL if not found                */
job_t *jobs_current_fg(void);          /* foreground job or NULL           */
void   jobs_list(void);                /* built-in `jobs` output           */
bool   jobs_have_stopped(void);        /* for `logout` guard               */
void jobs_shutdown(void);

#endif /* JOBS_H */
