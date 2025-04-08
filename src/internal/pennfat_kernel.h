#ifndef PENNFAT_KERNEL_H
#define PENNFAT_KERNEL_H

#include <stdint.h>
#include <stdbool.h>

#include "../common/pennfat_errors.h"

/* File Modes */
#define F_READ    1
#define F_WRITE   2
#define F_APPEND  3

/* lseek Whence Constants */
#define F_SEEK_SET 0
#define F_SEEK_CUR 1
#define F_SEEK_END 2

/* Initialization function: call this from your main application */
void pennfat_kernel_init(void);

/* Cleanup function: call this during application shutdown */
void pennfat_kernel_cleanup(void);

/* Kernel-Level API */
PennFatErr k_open(const char *fname, int mode);
PennFatErr k_close(int fd);
PennFatErr k_read(int fd, int n, char *buf);
PennFatErr k_write(int fd, const char *buf, int n);
PennFatErr k_unlink(const char *fname);
PennFatErr k_lseek(int fd, int offset, int whence);
PennFatErr k_ls(const char *fname);

/* Mount/Unmount */
PennFatErr k_mount(const char *fs_name);
PennFatErr k_unmount(void);
PennFatErr k_mkfs(const char *fs_name, int blocks_in_fat, int block_size_config);

#endif /* PENNFAT_KERNEL_H */
