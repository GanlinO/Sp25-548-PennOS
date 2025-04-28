#ifndef SYSCALL_KERNEL_H_
#define SYSCALL_KERNEL_H_

#include "../common/pennos_types.h"
#include "../internal/pennfat_kernel.h"

/* PennFAT wrappers --------------------------------------------------- */
int         s_open (const char *path, int mode);
PennFatErr  s_close(int fd);
PennFatErr  s_read (int fd, int n, char *buf);
PennFatErr  s_write(int fd, const char *buf, int n);

PennFatErr  s_touch (const char *path);
PennFatErr  s_ls    (const char *path /* or NULL = CWD */);
PennFatErr  s_chmod (const char *path, uint8_t perm);
int         s_rename(const char *oldp, const char *newp);   /* 0 / -1 */
int         s_unlink(const char *path);                     /* 0 / -1 */

/**
 * @brief Create a child process that executes the function `func`.
 * The child will retain some attributes of the parent.
 *
 * @param func Function to be executed by the child process.
 * @param argv Null-terminated array of args, including the command name as
 * argv[0].
 * @param fd0 Input file descriptor.
 * @param fd1 Output file descriptor.
 * @return pid_t The process ID of the created child process. Returns -1 on error.
 */
pid_t s_spawn(void* (*func)(void*), char* argv[], int fd0, int fd1);

/**
 * @brief Wait on a child of the calling process, until it changes state.
 * If `nohang` is true, this will not block the calling process and return
 * immediately.
 *
 * @param pid Process ID of the child to wait for. If set to -1, wait for any child.
 * @param wstatus Pointer to an integer variable where the status will be
 * stored.
 * @param nohang If true, return immediately if no child has exited.
 * @return pid_t The process ID of the child which has changed state on success,
 * -1 on error. If nohang is set and no child to wait for, returns 0.
 * @note Error no: ECHILD if the pid specified is not a child of the caller
 */
pid_t s_waitpid(pid_t pid, int* wstatus, bool nohang);

/**
 * @brief Send a signal to a particular process.
 *
 * @param pid Process ID of the target proces.
 * @param signal Signal number to be sent.
 * @return 0 on success, -1 on error.
 */
int s_kill(pid_t pid, int signal);

/**
 * @brief Unconditionally exit the calling process.
 */
void s_exit(void);

/**
 * @brief Set the priority of the specified thread.
 *
 * @param pid Process ID of the target thread.
 * @param priority The new priorty value of the thread (0, 1, or 2)
 * @return 0 on success, -1 on failure.
 */
int s_nice(pid_t pid, int priority);

/**
 * @brief Suspends execution of the calling proces for a specified number of
 * clock ticks.
 *
 * This function is analogous to `sleep(3)` in Linux, with the behavior that the
 * system clock continues to tick even if the call is interrupted. The sleep can
 * be interrupted by a P_SIGTERM signal, after which the function will return
 * prematurely.
 *
 * @param ticks Duration of the sleep in system clock ticks. Must be greater
 * than 0.
 */
void s_sleep(clock_tick_t ticks);

/**
 * @brief Set the terminal control to a process
 * @return 0 on success, -1 on error.
 */
int s_tcsetpid(pid_t pid);

/**
 * @brief Get the PID of the process itself
 * @return pid number on success, -1 on error
 */
pid_t s_getselfpid();

/**
 * @brief List all processes on PennOS, displaying PID, PPID, priority, status,
 * and command name.
 *
 */
void s_printprocess(void);

/**
 * User-space wrapper for k_pipe().
 * @param fds  int[2]; on success fds[0] is read, fds[1] is write.
 */
int s_pipe(int fds[2]);

#endif  // SYSCALL_KERNEL_H_