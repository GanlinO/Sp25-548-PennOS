#ifndef K_SYSCALLS_H
#define K_SYSCALLS_H

/* ------------------------------------------------------------------ */
/*  In-kernel “system-call” helpers                                    */
/*  (User-space uses s_open/s_read/…; kernel code uses the k_* ones.)  */
/* ------------------------------------------------------------------ */

#include <stddef.h>
#include <stdint.h>
#include "../internal/pennfat_kernel.h"   /* one true prototypes      */
#include <errno.h>                        /* ENOSYS */

/* whence arguments – keep them distinct from libc’s SEEK_* to avoid
   accidental mix-ups when we are −std=gnu2x and include <unistd.h>.   */
#define F_SEEK_SET   0
#define F_SEEK_CUR   1
#define F_SEEK_END   2

/* open() flags – keep it tiny for now, extend when you add modes      */
#define F_O_RDONLY   0x0001
#define F_O_WRONLY   0x0002
#define F_O_RDWR     0x0003
#define F_O_CREAT    0x0100   /* etc.                                  */


/* If you need a *temporary* dup helper, leave a stub here.
 * Remove once you implement a real k_dup() in PennFAT.              */
static inline int k_dup(int old_kfd)
{
    (void)old_kfd;
    errno = ENOSYS;
    return -1;
}


#endif /* K_SYSCALLS_H */
