#ifndef PENNFAT_KERNEL_H
#define PENNFAT_KERNEL_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* File Modes */
#define F_READ    1
#define F_WRITE   2
#define F_APPEND  3

/* lseek Whence Constants */
#define F_SEEK_SET 0
#define F_SEEK_CUR 1
#define F_SEEK_END 2

/* Kernel-Level API */
int k_open(const char *fname, int mode);
int k_close(int fd);
int k_read(int fd, int n, char *buf);
int k_write(int fd, const char *buf, int n);
int k_unlink(const char *fname);
int k_lseek(int fd, int offset, int whence);
int k_ls(const char *fname);

/* Mount/Unmount */
int mount_fs(const char *fs_name);
int unmount_fs(void);

#endif /* PENNFAT_KERNEL_H */
