#ifndef PENNFAT_KERNEL_H
#define PENNFAT_KERNEL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "../common/pennfat_errors.h"

/* Initialization function: call this from main application */
void pennfat_kernel_init(void);

/* Cleanup function: call this during application shutdown */
void pennfat_kernel_cleanup(void);

/* Kernel-Level API - File/Directory Operations */
PennFatErr k_open(const char *path, int mode);
PennFatErr k_close(int fd);
PennFatErr k_read(int fd, int n, char *buf);
PennFatErr k_write(int fd, const char *buf, int n);
PennFatErr k_unlink(const char *path);
PennFatErr k_lseek(int fd, int offset, int whence);
PennFatErr k_ls(const char *path);
PennFatErr k_touch(const char *path);
PennFatErr k_rename(const char *oldpath, const char *newpath);
PennFatErr k_chmod(const char *path, uint8_t perm);
PennFatErr k_mkdir(const char *path);
PennFatErr k_rmdir(const char *path);
PennFatErr k_symlink(const char *target, const char *linkpath);
typedef struct {
    uint8_t perm; 
} PennFatAttr;
PennFatErr k_getattr(const char *path, PennFatAttr *out);

/* Kernel-Level API - Process Context (will depend on PCB integration) */
PennFatErr k_chdir(const char *path);
PennFatErr k_getcwd(char *buf, size_t size);

/* Mount/Unmount */
PennFatErr k_mount(const char *fs_name);
PennFatErr k_unmount(void);
PennFatErr k_mkfs(const char *fs_name, int blocks_in_fat, int block_size_config);

#endif /* PENNFAT_KERNEL_H */