#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>  // IWYU pragma: keep [errno]

#include <sys/types.h>
#include <sys/mman.h>

#include "pennfat_kernel.h"
#include "../common/pennfat_errors.h"
#include "../common/pennfat_definitions.h"
#include "../util/logger.h"


// ---------------------------------------------------------------------------
// 0) LOGGING PURPOSEES
// ---------------------------------------------------------------------------

/* Static logger pointer for this module */
static Logger *logger = NULL;

/* Initialization function: call this from your main application */
void pennfat_kernel_init(void) {
    LOGGER_INIT("pennfat_kernel", LOG_LEVEL_DEBUG);
}

/* Cleanup function: call this during application shutdown */
void pennfat_kernel_cleanup(void) {
    LOGGER_CLOSE();
    printf("PennFAT kernel module cleaned up.\n");
}


// ---------------------------------------------------------------------------
// 1) DEFINITIONS AND CONSTANTS
// ---------------------------------------------------------------------------

/* FAT entry definitions */
#define FAT_FREE  0x0000
#define FAT_EOC   0xFFFF  // End-Of-Chain

/* Table sizes */
#define MAX_SYSTEM_FILES 64  // Subject to chanage; maximum number of system-wide file entries
#define MAX_FD 32            // Subject to change; max number of open file descriptors
#define MAX_DIR_ENTRIES 128  // Subject to change; maximum number of entries in the root directory

/* Allowed block sizes mapping */
static const int block_sizes[] = {256, 512, 1024, 2048, 4096};


// ---------------------------------------------------------------------------
// 2) DATA STRUCTURES
// ---------------------------------------------------------------------------

/* System-Wide File Table Entry */
typedef struct {
    int      ref_count;   // Number of FDs referencing this file
    bool     in_use;      // Whether this entry is active
    uint16_t first_block; // Starting block (from directory)
    uint32_t size;        // File size in bytes
    time_t   mtime;       // Last modification time
    int      dir_index;   // Index in the directory array
} system_file_t;
static system_file_t g_sysfile_table[MAX_SYSTEM_FILES];

/* File Descriptor Table Entry */
// typedef struct {
//     bool     in_use;        // FD slot is active
//     int      sysfile_index; // Index into system-wide file table
//     int      mode;          // F_READ, F_WRITE, or F_APPEND
//     uint32_t offset;        // Current file pointer offset
// } fd_entry_t;
static fd_entry_t g_fd_table[MAX_FD];

/* PennFAT directory entry: fixed 64 bytes */
// typedef struct {
//     char     name[32];     // 32-byte null-terminated file name.
//                            // Special markers: 0 = end of directory, 1 = deleted, 2 = deleted but in use.
//     uint32_t size;         // 4 bytes: file size in bytes.
//     uint16_t first_block;   // 2 bytes: first block number (undefined if size is zero).
//     uint8_t  type;         // 1 byte: file type (0: unknown, 1: regular, 2: directory, 4: symbolic link).
//     uint8_t  perm;         // 1 byte: permissions (0, 2, 4, 5, 6, or 7).
//     time_t   mtime;        // 8 bytes: creation/modification time.
//     char     reserved[16]; // 16 bytes reserved.
// } __attribute__((packed)) dir_entry_t;  // Ensure no padding
static dir_entry_t *g_root_dir;

/* FAT Array (in memory) */
static uint16_t *g_fat = NULL;

/* Superblock Structure */
typedef struct {
    // uint32_t magic;
    uint32_t block_size;       // Bytes per block
    uint32_t fat_start_block;  // Starting block of FAT region
    uint32_t fat_block_count;  // Number of blocks for FAT
    uint32_t root_start_block; // Starting block of root directory
    uint32_t root_block_count; // Number of blocks for directory
    uint32_t data_start_block; // Starting block of data region
} superblock_t;
static superblock_t g_superblock;

/* Global variables for host FS access and mounting */
static int g_mounted = 0;
static int g_fs_fd = -1;
static uint32_t g_block_size = 0;  // actual block size (computed from block_size_config)


// ---------------------------------------------------------------------------
// 3) HELPER ROUTINES
// ---------------------------------------------------------------------------

/* 
 * read_block: Reads a block from the underlying filesystem using the file descriptor.
 * It calculates the offset as block_index * g_block_size.
 */
 static int read_block(void *buf, uint32_t block_index) {
    if (g_fs_fd < 0)
        return -1;
    
    off_t offset = block_index * g_block_size;
    if (lseek(g_fs_fd, offset, SEEK_SET) < 0)
        return -1;
    
    ssize_t bytes_read = read(g_fs_fd, buf, g_block_size);
    if (bytes_read != g_block_size)
        return -1;
    
    return 0;
}

/* 
 * write_block: Writes a block to the underlying filesystem using the file descriptor.
 * It computes the offset as block_index * g_block_size and writes exactly g_block_size bytes.
 */
static int write_block(const void *buf, uint32_t block_index) {
    if (g_fs_fd < 0)
        return -1;
    
    off_t offset = block_index * g_block_size;
    if (lseek(g_fs_fd, offset, SEEK_SET) < 0)
        return -1;
    
    ssize_t bytes_written = write(g_fs_fd, buf, g_block_size);
    if (bytes_written != g_block_size)
        return -1;
    
    return 0;
}

/* locate_block_in_chain: Given a file offset, find the physical block and offset */
static int locate_block_in_chain(uint16_t start_block,
                                 uint32_t file_offset,
                                 uint16_t *block_out,
                                 uint32_t *offset_in_block) {
    if (start_block == FAT_FREE || start_block == FAT_EOC)
        return -1;
    uint32_t block_count = file_offset / g_block_size;
    *offset_in_block = file_offset % g_block_size;
    uint16_t current = start_block;
    for (uint32_t i = 0; i < block_count; i++) {
        if (current == FAT_EOC)
            return -1;
        current = g_fat[current];
    }
    *block_out = current;
    return 0;
}

/* allocate_free_block: Finds a free block in the FAT and marks it as allocated */
static int allocate_free_block(void) {
    uint32_t total_entries = (g_superblock.fat_block_count * g_block_size) / sizeof(uint16_t);
    for (uint32_t i = g_superblock.data_start_block; i < total_entries; i++) {
        if (g_fat[i] == FAT_FREE) {
            g_fat[i] = FAT_EOC;
            return i;
        }
    }
    return -1;
}


// ---------------------------------------------------------------------------
// 3) SYSTEM-WIDE FILE TABLE (SWFT) HELPERS
// ---------------------------------------------------------------------------

/* create_sysfile_entry: Create a new system file entry for a directory index */
static int create_sysfile_entry(int dir_index) {
    for (int i = 0; i < MAX_SYSTEM_FILES; i++) {
        if (!g_sysfile_table[i].in_use) {
            g_sysfile_table[i].in_use = true;
            g_sysfile_table[i].ref_count = 1;
            g_sysfile_table[i].dir_index = dir_index;
            g_sysfile_table[i].first_block = g_root_dir[dir_index].first_block;
            g_sysfile_table[i].size = g_root_dir[dir_index].size;
            g_sysfile_table[i].mtime = g_root_dir[dir_index].mtime;
            return i;
        }
    }
    return -1;
}

/* find_and_increment_sysfile: If the file is already open, increment its ref count */
static int find_and_increment_sysfile(int dir_index) {
    for (int i = 0; i < MAX_SYSTEM_FILES; i++) {
        if (g_sysfile_table[i].in_use && g_sysfile_table[i].dir_index == dir_index) {
            g_sysfile_table[i].ref_count++;
            return i;
        }
    }
    return -1;
}

/* release_sysfile_entry: Decrement ref count and free if it reaches zero */
static void release_sysfile_entry(int sys_idx) {
    if (sys_idx < 0 || sys_idx >= MAX_SYSTEM_FILES)
        return;
    if (!g_sysfile_table[sys_idx].in_use)
        return;

    g_sysfile_table[sys_idx].ref_count--;
    if (g_sysfile_table[sys_idx].ref_count <= 0) {
        int d_idx = g_sysfile_table[sys_idx].dir_index;
        g_root_dir[d_idx].size = g_sysfile_table[sys_idx].size;
        g_root_dir[d_idx].mtime = g_sysfile_table[sys_idx].mtime;
        g_root_dir[d_idx].first_block = g_sysfile_table[sys_idx].first_block;
        memset(&g_sysfile_table[sys_idx], 0, sizeof(system_file_t));
    }
}


// ---------------------------------------------------------------------------
// 4) KERNEL-LEVEL APIs
// ---------------------------------------------------------------------------

/**
 * Open a file name `fname` with the mode and return a file descriptor (fd).
 * The allowed modes are as follows:
 *   - F_WRITE: writing and reading, truncates if the file exists, or creates
 *              it if it does not exist. Only one instance of a file can be
 *              opened in F_WRITE mode at a time; error if attempted to open a
 *              file in F_WRITE mode more than once
 *   - F_READ:  open the file for reading only, return an error if the file
 *              does not exist
 *   - F_APPEND: open the file for reading and writing but does not truncate the
 *               file if exists; additionally, the file pointer references the
 *               end of the file
 */
PennFatErr k_open(const char *fname, int mode) {
    if (!g_mounted) {
        LOG_WARN("[k_open] Failed to open file '%s': Filesystem not mounted.", fname);
        return PennFatErr_NOT_MOUNTED; 
    }

    int found_idx = -1, free_idx = -1;
    for (int i = 0; i < MAX_DIR_ENTRIES; i++) {
        if (g_root_dir[i].name[0] == '\0') {
            if (free_idx < 0) {
                free_idx = i;
                LOG_DEBUG("[k_open] Found free directory entry at index %d for file '%s'.", i, fname);
            }
                
        } else if (strncmp(g_root_dir[i].name, fname, sizeof(g_root_dir[i].name)) == 0) {
            found_idx = i;
            LOG_DEBUG("[k_open] Found existing file entry at index %d for file '%s'.", i, fname);
            break;
        }
    }

    if (found_idx < 0) {
        if (mode == F_READ) {
            LOG_INFO("[k_open] Failed to open file '%s': File does not exist.", fname);
            return PennFatErr_EXISTS;
        }
        if (free_idx < 0) {
            LOG_ERR("[k_open] Failed to open file '%s': No free directory entries available for new file.", fname);
            return PennFatErr_OUTOFMEM;
        }

        found_idx = free_idx;
        memset(&g_root_dir[found_idx], 0, sizeof(dir_entry_t));
        strncpy(g_root_dir[found_idx].name, fname, sizeof(g_root_dir[found_idx].name) - 1);
        g_root_dir[found_idx].name[sizeof(g_root_dir[found_idx].name) - 1] = '\0';
        g_root_dir[found_idx].size = 0;
        g_root_dir[found_idx].mtime = time(NULL);
        int new_blk = allocate_free_block();

        if (new_blk < 0) {
            LOG_ERR("[k_open] Failed to allocate a new block for file '%s': No free blocks available.", fname);
            return PennFatErr_NOSPACE;  // No free blocks available to allocate for the new file
        }

        g_root_dir[found_idx].first_block = new_blk;
        LOG_DEBUG("[k_open] Created new file entry for '%s' at index %d with starting block %u.", 
                  fname, found_idx, g_root_dir[found_idx].first_block);
    } else {
        if (mode == F_WRITE) {
            /* Truncate file: free all blocks after the first */
            uint16_t first = g_root_dir[found_idx].first_block;
            uint16_t next = g_fat[first];
            g_fat[first] = FAT_EOC;
            while (next != FAT_EOC) {
                uint16_t temp = g_fat[next];
                g_fat[next] = FAT_FREE;
                next = temp;
            }
            g_root_dir[found_idx].size = 0;
            g_root_dir[found_idx].mtime = time(NULL);

            LOG_DEBUG("[k_open] Truncated file '%s' at index %d, cleared all blocks after the first.", 
                      fname, found_idx);
        }
    }

    int sys_idx = find_and_increment_sysfile(found_idx);
    if (sys_idx < 0) {
        sys_idx = create_sysfile_entry(found_idx);
        if (sys_idx < 0) {
            LOG_ERR("[k_open] Failed to create a new system file entry for file '%s': No more system file slots available.", 
                    fname);
            return PennFatErr_OUTOFMEM; /* Failed to create a new system file entry */
        }
    }
    LOG_DEBUG("[k_open] Successfully found or created system file entry at index %d for file '%s'.", 
              sys_idx, fname);

    for (int fd = 0; fd < MAX_FD; fd++) {
        if (!g_fd_table[fd].in_use) {
            g_fd_table[fd].in_use = true;
            g_fd_table[fd].sysfile_index = sys_idx;
            g_fd_table[fd].mode = mode;
            g_fd_table[fd].offset = (mode == F_APPEND) ? g_sysfile_table[sys_idx].size : 0;

            LOG_INFO("[k_open] Assigned file descriptor %d for file '%s'",
                     fd, fname);
            LOG_DEBUG("[k_open] File descriptor %d initialized with sysfile index %d, mode %d, and offset %u.",
                      fd, sys_idx, mode, g_fd_table[fd].offset);

            return fd;
        }
    }

    release_sysfile_entry(sys_idx);
    LOG_ERR("[k_open] Failed to find a free file descriptor for file '%s': Maximum number of open file descriptors reached (%d).",
          fname, MAX_FD);

    return PennFatErr_OUTOFMEM;
}

/**
 * Read n bytes from the file referenced by fd. On return, k_read returns the
 * number of bytes read, 0 if EOF is reached, or a negative number on error.
 */
PennFatErr k_read(int fd, int n, char *buf) {
    if (!g_mounted) {
        LOG_WARN("[k_read] Failed to read from file descriptor %d: Filesystem not mounted.", fd);
        return PennFatErr_NOT_MOUNTED;
    }

    if (fd < 0 || fd >= MAX_FD || !g_fd_table[fd].in_use) {
        LOG_ERR("[k_read] Failed to read from file descriptor %d: Invalid file descriptor or not in use.", fd);
        return PennFatErr_INTERNAL;
    }

    fd_entry_t *fdesc = &g_fd_table[fd];
    int sys_idx = fdesc->sysfile_index;
    system_file_t *sf = &g_sysfile_table[sys_idx];

    LOG_DEBUG("[k_read] Attempting to read from file descriptor %d (sysfile index %d, offset %u, size %u).",
              fd, sys_idx, fdesc->offset, sf->size);

    if (fdesc->mode == F_WRITE) {
        LOG_WARN("[k_read] Cannot read from file descriptor %d: File opened in write-only mode.", fd);
        return PennFatErr_PERM;
    }

    uint32_t size_left = (sf->size > fdesc->offset) ? sf->size - fdesc->offset : 0;
    if (size_left == 0) {
        LOG_INFO("[k_read] Reached EOF for file descriptor %d (sysfile index %d): No more data to read.", 
                 fd, sys_idx);
        return PennFatErr_SUCCESS;
    }

    int to_read = (n < (int)size_left) ? n : (int)size_left;
    int total_read = 0;
    char *block_buf = malloc(g_block_size);
    if (!block_buf) {
        LOG_ERR("[k_read] Failed to allocate buffer for reading from file descriptor %d: Out of memory.", fd);
        return PennFatErr_INTERNAL;
    }

    LOG_INFO("[k_read] Reading %d bytes from file descriptor %d (sysfile index %d) starting at offset %u.",
             to_read, fd, sys_idx, fdesc->offset);

    while (total_read < to_read) {
        uint16_t block_num;
        uint32_t offset_in_block;

        if (locate_block_in_chain(sf->first_block, fdesc->offset, &block_num, &offset_in_block) < 0)
            break;
        if (read_block(block_buf, block_num) < 0)
            break;

        uint32_t chunk = g_block_size - offset_in_block;
        int remain = to_read - total_read;
        if (chunk > (uint32_t)remain)
            chunk = remain;

        memcpy(buf + total_read, block_buf + offset_in_block, chunk);
        total_read += chunk;
        fdesc->offset += chunk;
    }

    free(block_buf);
    return total_read;
}

/**
 * Write n bytes of the string referenced by str to the file fd and increment
 * the file pointer by n. On return, k_write returns the number of bytes 
 * written, or a negative value on error. Note that this writes bytes not chars,
 * these can be anything, even '\0'.
 */
PennFatErr k_write(int fd, const char *buf, int n) {
    if (!g_mounted) {
        LOG_WARN("[k_write] Failed to write to file descriptor %d: Filesystem not mounted.", fd);
        return PennFatErr_NOT_MOUNTED;
    }

    if (fd < 0 || fd >= MAX_FD || !g_fd_table[fd].in_use) {
        LOG_ERR("[k_write] Failed to write to file descriptor %d: Invalid file descriptor or not in use.", fd);
        return PennFatErr_INTERNAL; 
    }

    fd_entry_t *fdesc = &g_fd_table[fd];
    int sys_idx = fdesc->sysfile_index;
    system_file_t *sf = &g_sysfile_table[sys_idx];

    LOG_DEBUG("[k_write] Attempting to write to file descriptor %d (sysfile index %d, offset %u).",
              fd, sys_idx, fdesc->offset);

    if (fdesc->mode == F_READ) {
        LOG_WARN("[k_write] Cannot write to file descriptor %d: File opened in read-only mode.", fd);
        return PennFatErr_PERM; /* Cannot write in read-only mode */
    }

    int total_written = 0;
    char *block_buf = malloc(g_block_size);
    if (!block_buf) {
        LOG_ERR("[k_write] Failed to allocate buffer for writing to file descriptor %d: Out of memory.", fd);
        return PennFatErr_INTERNAL;
    }

    while (total_written < n) {
        uint16_t block_num;
        uint32_t offset_in_block;

        if (locate_block_in_chain(sf->first_block, fdesc->offset, &block_num, &offset_in_block) < 0) {
            /* Need to allocate a new block */
            uint16_t last = sf->first_block;
            while (g_fat[last] != FAT_EOC)
                last = g_fat[last];
            int newblk = allocate_free_block();
            if (newblk < 0)
                break;
            g_fat[last] = (uint16_t)newblk;
            block_num = (uint16_t)newblk;
            offset_in_block = 0;
        }

        if (read_block(block_buf, block_num) < 0)
            break;

        uint32_t chunk = g_block_size - offset_in_block;
        int remain = n - total_written;
        if (chunk > (uint32_t)remain)
            chunk = remain;

        memcpy(block_buf + offset_in_block, buf + total_written, chunk);
        if (write_block(block_buf, block_num) < 0)
            break;

        total_written += chunk;
        fdesc->offset += chunk;
        if (fdesc->offset > sf->size) {
            sf->size = fdesc->offset;
            sf->mtime = time(NULL);
        }
    }

    LOG_INFO("[k_write] Successfully wrote %d bytes to file descriptor %d (sysfile index %d). New file size is %u bytes.",
             total_written, fd, sys_idx, sf->size);

    free(block_buf);
    return total_written;
}

/**
 * Close the file fd and return 0 on success, or a negative value on failure.
 */
PennFatErr k_close(int fd) {
    if (!g_mounted) {
        LOG_WARN("[k_close] Failed to close file descriptor %d: Filesystem not mounted.", fd);
        return PennFatErr_NOT_MOUNTED;
    }

    if (fd < 0 || fd >= MAX_FD || !g_fd_table[fd].in_use) {
        LOG_ERR("[k_close] Failed to close file descriptor %d: Invalid file descriptor or not in use.", fd);
        return PennFatErr_INTERNAL;
    }

    fd_entry_t *fdesc = &g_fd_table[fd];
    int sys_idx = fdesc->sysfile_index;
    fdesc->in_use = false;
    release_sysfile_entry(sys_idx);

    LOG_INFO("[k_close] Successfully closed file descriptor %d (sysfile index %d).", fd, sys_idx);

    return 0;
}

/** 
 * Remove the file. Be careful how you implement this, like Linux, you should 
 * not be able to delete a file that is in use by another process. Furthermore,
 * consider where updates will be necessary. You do not necessarily need to clear
 * the previous data in the data region, but should at least note this area as
 * ‘nullified’ or fresh and ready to write to, elsewhere. 
 */
PennFatErr k_unlink(const char *fname) {
    if (!g_mounted) {
        LOG_WARN("[k_unlink] Failed to unlink file '%s': Filesystem not mounted.", fname);
        return PennFatErr_NOT_MOUNTED; 
    }

    int dir_index = -1;
    for (int i = 0; i < MAX_DIR_ENTRIES; i++) {
        if (strncmp(g_root_dir[i].name, fname, sizeof(g_root_dir[i].name)) == 0) {
            dir_index = i;
            break;
        }
    }

    if (dir_index < 0) {
        LOG_ERR("[k_unlink] Failed to unlink file '%s': File does not exist.", fname);
        return PennFatErr_EXISTS; /* File not found */
    }

    for (int i = 0; i < MAX_SYSTEM_FILES; i++) {
        if (g_sysfile_table[i].in_use && g_sysfile_table[i].dir_index == dir_index) {
            LOG_WARN("[k_unlink] Failed to unlink file '%s': File is currently in use by another process (sysfile index %d).",
                     fname, i);
            return PennFatErr_INUSE;
        }
    }

    uint16_t cur = g_root_dir[dir_index].first_block;
    while (cur != FAT_EOC) {
        uint16_t nxt = g_fat[cur];
        g_fat[cur] = FAT_FREE;
        cur = nxt;
    }
    memset(&g_root_dir[dir_index], 0, sizeof(dir_entry_t));

    LOG_INFO("[k_unlink] Successfully unlinked file '%s' from directory entry %d.", fname, dir_index);
    return 0;
}

/**
 * Reposition the file pointer for fd to the offset relative to whence.
 * You must also implement the constants F_SEEK_SET, F_SEEK_CUR, and F_SEEK_END,
 * which reference similar file whences as their similarly named counterparts 
 * in lseek(2). Note that this could require updates to the metadata of the file,
 * for example, if the new position of n exceeds the files previous filesize!
 */
PennFatErr k_lseek(int fd, int offset, int whence) {
    if (!g_mounted) {
        LOG_WARN("[k_lseek] Failed to seek in file descriptor %d: Filesystem not mounted.", fd);
        return PennFatErr_NOT_MOUNTED;
    }

    if (fd < 0 || fd >= MAX_FD || !g_fd_table[fd].in_use) {
        LOG_ERR("[k_lseek] Failed to seek in file descriptor %d: Invalid file descriptor or not in use.", fd);
        return PennFatErr_INTERNAL;
    }

    fd_entry_t *fdesc = &g_fd_table[fd];
    int sys_idx = fdesc->sysfile_index;
    system_file_t *sf = &g_sysfile_table[sys_idx];

    LOG_DEBUG("[k_lseek] Attempting to seek in file descriptor %d (sysfile index %d) to offset %d from whence %d.",
              fd, sys_idx, offset, whence);

    int new_offset = 0;
    switch (whence) {
        case F_SEEK_SET:
            new_offset = offset;
            break;
        case F_SEEK_CUR:
            new_offset = (int)fdesc->offset + offset;
            break;
        case F_SEEK_END:
            new_offset = (int)sf->size + offset;
            break;
        default:
            LOG_ERR("[k_lseek] Failed to seek in file descriptor %d: Unknown whence value %d.", fd, whence);
            return PennFatErr_INVAD;
    }

    if (new_offset < 0) {
        LOG_ERR("[k_lseek] Failed to seek in file descriptor %d: New offset %d is negative.", fd, new_offset);
        return PennFatErr_INVAD; /* Cannot seek to a negative offset */
    }

    fdesc->offset = (uint32_t)new_offset;
    LOG_INFO("[k_lseek] Successfully sought in file descriptor %d (sysfile index %d) to new offset %u.",
             fd, sys_idx, fdesc->offset);

    return fdesc->offset;
}

/**
 * List the file filename in the current directory. If filename is NULL, list all
 * files in the current directory. This should act as very similar to posix,
 * displaying the first block of the file, its permissions (you can leave this for
 * the time being, chmod will be required to be implemented later), size, latest
 * modification timestamp and filename.
 */
PennFatErr k_ls(const char *fname) {
    if (!g_mounted) {
        LOG_WARN("[k_ls] Failed to list files: Filesystem not mounted.");
        return PennFatErr_NOT_MOUNTED; 
    }

    /* Buffer to hold formatted time */
    char time_buf[20];
    struct tm *tm_info;

    if (fname && fname[0] != '\0') {
        for (int i = 0; i < MAX_DIR_ENTRIES; i++) {
            if (strncmp(g_root_dir[i].name, fname, sizeof(g_root_dir[i].name)) == 0) {
                tm_info = localtime(&g_root_dir[i].mtime);
                strftime(time_buf, sizeof(time_buf), "%b %d %H:%M", tm_info);

                // TODO: [Permissions] using a placeholder "rw-" for now
                printf("%5u  %-4s  %10u  %s  %s\n", 
                       g_root_dir[i].first_block, "rw-", g_root_dir[i].size, time_buf, g_root_dir[i].name);
                return 0;
            }
        }

        LOG_WARN("[k_ls] Failed to list file '%s': File not found in the directory.", fname);
        return PennFatErr_EXISTS;
    } else {
        for (int i = 0; i < MAX_DIR_ENTRIES; i++) {
            if (g_root_dir[i].name[0] != '\0') {
                tm_info = localtime(&g_root_dir[i].mtime);
                strftime(time_buf, sizeof(time_buf), "%b %d %H:%M", tm_info);
                printf("%5u  %-4s  %10u  %s  %s\n", 
                       g_root_dir[i].first_block, "rw-", g_root_dir[i].size, time_buf, g_root_dir[i].name);
            }
        }
        return 0;
    }
}

/* --- Mount/Unmount Functions --- */

/*
 * mount: Mounts the PennFAT filesystem.
 * The FAT region (of predetermined size) is mapped starting at offset 0.
 * The superblock functionality is implemented by reading FAT[0]:
 *   - The least-significant byte (LSB) is the block_size_config.
 *   - The most-significant byte (MSB) is the number of FAT blocks.
 * Based on that, we compute g_block_size and the FAT region size, and then
 * read the root directory from the first data block.
 */
PennFatErr k_mount(const char *fs_name) {
    if (g_mounted) {
        LOG_WARN("[k_mount] Failed to mount filesystem '%s': Already mounted.", fs_name);
        return PennFatErr_UNEXPCMD;
    }

    /* Open the filesystem file using open(2) for read/write */
    int fd = open(fs_name, O_RDWR);
    if (fd < 0) {
        LOG_CRIT("[k_mount] Failed to open filesystem file '%s': %s", fs_name, strerror(errno));
        return PennFatErr_INTERNAL;
    }
    g_fs_fd = fd;

    /* Read the first 2 bytes from the file to get FAT[0] (the superblock info) */
    uint16_t super_entry;
    ssize_t rd = read(fd, &super_entry, sizeof(super_entry));
    if (rd != sizeof(super_entry)) {
        LOG_CRIT("[k_mount] Failed to read superblock from filesystem file '%s': %s", fs_name, strerror(errno));
        close(fd);
        return PennFatErr_INTERNAL;
    }

    /* Interpret FAT[0] in little-endian format:
       - LSB (lower 8 bits) is block_size_config (0–4).
       - MSB (upper 8 bits) is the number of FAT blocks.
    */
    uint8_t block_size_config = super_entry & 0xFF;
    uint8_t fat_blocks = (super_entry >> 8) & 0xFF;
    
    if (block_size_config > 4) {
        LOG_ERR("[k_mount] Invalid block size config: %u", block_size_config);
        close(fd);
        return PennFatErr_INVAD;
    }
    if (fat_blocks < 1 || fat_blocks > 32) {
        LOG_ERR("[k_mount] Invalid number of FAT blocks: %u", fat_blocks);
        close(fd);
        return PennFatErr_INVAD;
    }

    /* Compute the actual block size */
    g_block_size = block_sizes[block_size_config];
    
    /* Compute the FAT region size (in bytes) */
    uint32_t fat_region_size = fat_blocks * g_block_size;

    LOG_DEBUG("[k_mount] Mounting filesystem '%s' with block size %u bytes and %u FAT blocks.",
              fs_name, g_block_size, fat_blocks);

    /* Map the FAT region into memory using mmap(2).
       The FAT region is stored at offset 0.
    */
    g_fat = mmap(NULL, fat_region_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (g_fat == MAP_FAILED) {
        LOG_CRIT("[k_mount] Failed to map FAT region from filesystem file '%s': %s", fs_name, strerror(errno));
        close(fd);
        return PennFatErr_INTERNAL;
    }

    /* Optionally verify that the mapped FAT[0] matches the super_entry we read */
    if (g_fat[0] != super_entry) {
        LOG_CRIT("[k_mount] FAT[0] mismatch: expected 0x%04x, got 0x%04x", super_entry, g_fat[0]);
        munmap(g_fat, fat_region_size);
        close(fd);
        return PennFatErr_INTERNAL;
    }

     /* Read the root directory region.
       According to our mkfs, the root directory is stored in the first data block,
       which immediately follows the FAT region. Its size is one block (g_block_size bytes).
       Compute the offset for the root directory:
           root_offset = fat_region_size
    */
    off_t root_offset = fat_region_size;
    g_root_dir = malloc(g_block_size);
    if (!g_root_dir) {
        LOG_CRIT("[k_mount] Failed to allocate memory for root directory: %s", strerror(errno));
        munmap(g_fat, fat_region_size);
        close(fd);
        return PennFatErr_OUTOFMEM;
    }
    
    if (lseek(fd, root_offset, SEEK_SET) < 0) {
        LOG_CRIT("[k_mount] Failed to seek to root directory in filesystem file '%s': %s", fs_name, strerror(errno));
        free(g_root_dir);
        munmap(g_fat, fat_region_size);
        close(fd);
        return PennFatErr_INTERNAL;
    }
    
    if (read(fd, g_root_dir, g_block_size) != (ssize_t)g_block_size) {
        LOG_CRIT("[k_mount] Failed to read root directory from filesystem file '%s': %s", fs_name, strerror(errno));
        free(g_root_dir);
        munmap(g_fat, fat_region_size);
        close(fd);
        return PennFatErr_INTERNAL;
    }

    LOG_DEBUG("[k_mount] Successfully read root directory from offset %u in filesystem file '%s'.",
              root_offset, fs_name);

    /* Clear system-wide and FD tables (if necessary) */
    memset(g_sysfile_table, 0, sizeof(g_sysfile_table));
    memset(g_fd_table, 0, sizeof(g_fd_table));

    LOG_INFO("[k_mount] Successfully mounted filesystem '%s' with block size %u bytes.", fs_name, g_block_size);

    g_mounted = 1;
    return PennFatErr_SUCCESS;
}

/* unmount: Writes back the FAT and root directory to disk, then unmaps and closes the FS */
PennFatErr k_unmount(void) {
    if (!g_mounted) {
        LOG_WARN("[k_unmount] Failed to unmount filesystem: Not mounted.");
        return PennFatErr_NOT_MOUNTED;
    }

    /* Recompute FAT region size:
       FAT[0] contains the formatting info:
         MSB = number of FAT blocks
       Calculate:
         fat_blocks = (g_fat[0] >> 8) & 0xff
         fat_region_size = fat_blocks * g_block_size
    */
    uint8_t fat_blocks = (g_fat[0] >> 8) & 0xff;
    uint32_t fat_region_size = fat_blocks * g_block_size;

    LOG_DEBUG("[k_unmount] Unmounting filesystem with %u FAT blocks, block size %u bytes.",
              fat_blocks, g_block_size);

    /* First, write back the root directory region.
       The root directory is stored in the first data block, located at:
           root_offset = fat_region_size (since FAT region occupies the first fat_region_size bytes)
       The size of the root directory region is one block (g_block_size bytes).
    */
    off_t root_offset = fat_region_size;
    if (lseek(g_fs_fd, root_offset, SEEK_SET) < 0) {
        LOG_CRIT("[k_unmount] Failed to seek to root directory in filesystem file: %s", strerror(errno));
        return PennFatErr_INTERNAL;
    }
    if (write(g_fs_fd, g_root_dir, g_block_size) != (ssize_t)g_block_size) {
        LOG_CRIT("[k_unmount] Failed to write root directory to filesystem file: %s", strerror(errno));
        return PennFatErr_INTERNAL;
    }

    /* Synchronize the mapped FAT region to disk */
    if (msync(g_fat, fat_region_size, MS_SYNC) < 0) {
        LOG_CRIT("[k_unmount] Failed to synchronize FAT region to disk: %s", strerror(errno));
        return PennFatErr_INTERNAL;
    }

    /* Unmap the FAT region */
    if (munmap(g_fat, fat_region_size) < 0) {
        LOG_CRIT("[k_unmount] Failed to unmap FAT region: %s", strerror(errno));
        return PennFatErr_INTERNAL;
    }
    g_fat = NULL;

    /* Free the allocated root directory buffer */
    free(g_root_dir);
    g_root_dir = NULL;

    /* Close the filesystem file */
    if (close(g_fs_fd) < 0) {
        LOG_ERR("[k_unmount] Failed to close filesystem file: %s", strerror(errno));
        return -1;
    }
    g_fs_fd = -1;

    LOG_INFO("[k_unmount] Successfully unmounted filesystem.");

    g_mounted = 0;
    return 0;
}

/**
 * mkfs: Creates a new PennFAT filesystem.
 * Usage: mkfs FS_NAME BLOCKS_IN_FAT BLOCK_SIZE_CONFIG
 *
 * BLOCKS_IN_FAT must be between 1 and 32.
 * BLOCK_SIZE_CONFIG must be between 0 and 4, which maps to:
 *   0: 256 bytes, 1: 512 bytes, 2: 1024 bytes, 3: 2048 bytes, 4: 4096 bytes.
 * 
 * The FAT is placed at the very beginning of the filesystem image.
 * The first FAT entry (FAT[0]) stores formatting info:
 *     MSB = blocks_in_fat, LSB = block_size_config.
 * FAT[1] is set to FAT_EOC, designating that the first data block (Block 1, which is
 * the root directory file’s first block) is allocated.
 * The data region size is: block_size * (number of FAT entries - 1).
 */
PennFatErr k_mkfs(const char *fs_name, int blocks_in_fat, int block_size_config) {
    /* Check if a filesystem is already mounted */
    if (g_mounted) {
        LOG_WARN("[k_mkfs] Cannot create a new filesystem while one is already mounted.");
        return PennFatErr_UNEXPCMD;
    }
    
    /* Validate parameters */
    if (blocks_in_fat < 1 || blocks_in_fat > 32) {
        LOG_ERR("[k_mkfs] Invalid number of blocks in FAT. Must be between 1 and 32.");
        return PennFatErr_INVAD;
    }
    if (block_size_config < 0 || block_size_config > 4) {
        LOG_ERR("[k_mkfs] Invalid block size configuration. Must be between 0 and 4.");
        return PennFatErr_INVAD;
    }
    uint32_t block_size = block_sizes[block_size_config];
    
    /* Calculate region sizes:
     * FAT region size = blocks_in_fat * block_size.
     * Number of FAT entries = FAT region size / 2.
     * Data region size = block_size * (number of FAT entries - 1).
     * Total FS size = FAT region size + Data region size.
     */
    uint32_t fat_region_size = blocks_in_fat * block_size;
    uint32_t fat_entries = fat_region_size / sizeof(uint16_t);  // each entry is 2 bytes
    uint32_t data_blocks = (fat_entries - 1) - ((fat_entries - 1) == 0xFFFF);  // subtract one for FAT[0]
                                                                               // subtract one for xFFFF
    uint32_t data_region_size = data_blocks * block_size;
    uint32_t total_fs_size = fat_region_size + data_region_size;

    LOG_DEBUG("[k_mkfs] Creating filesystem with %d blocks in FAT, block size %u bytes, total size %u bytes.",
              blocks_in_fat, block_size, total_fs_size);

    /* Open (or create) the filesystem file */
    int fd = open(fs_name, O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        LOG_CRIT("[k_mkfs] Failed to open/create filesystem file '%s': %s", fs_name, strerror(errno));
        return PennFatErr_INTERNAL;
    }

    /* Set the file size to total_fs_size bytes */
    if (ftruncate(fd, total_fs_size) < 0) {
        perror("mkfs: ftruncate");
        close(fd);
        return -1;
    }
    
    /* Allocate and initialize the FAT array */
    uint16_t *fat_array = malloc(fat_region_size);
    if (!fat_array) {
        perror("mkfs: malloc (fat_array)");
        close(fd);
        return -1;
    }
    uint32_t num_entries = fat_region_size / sizeof(uint16_t);
    for (uint32_t i = 0; i < num_entries; i++) {
        fat_array[i] = FAT_FREE;
    }

    /* Set formatting info in FAT[0]: 
       MSB = blocks_in_fat, LSB = block_size_config.
       For example, if blocks_in_fat = 32 and block_size_config = 4, FAT[0] = 0x2004.
    */
    fat_array[0] = ((uint16_t)blocks_in_fat << 8) | (uint16_t)block_size_config;

    /* Set FAT[1] to FAT_EOC so that the root directory's first block is allocated and marked as the end of chain */
    fat_array[1] = FAT_EOC;
    
    /* Write the FAT region at offset 0 */
    if (lseek(fd, 0, SEEK_SET) < 0) {
        perror("mkfs: lseek (FAT region)");
        free(fat_array);
        close(fd);
        return -1;
    }
    if (write(fd, fat_array, fat_region_size) != fat_region_size) {
        perror("mkfs: write (FAT region)");
        free(fat_array);
        close(fd);
        return -1;
    }
    free(fat_array);
    
    /* Initialize the root directory region.
       The root directory is stored in the first data block (Block 1).
       We'll zero out one block (block_size bytes) at offset = fat_region_size.
       (If the entire FS image is already zeroed by ftruncate, this might be optional,
       but it's good to explicitly set the root directory.)
    */
    char *zero_buf = calloc(1, block_size);
    if (!zero_buf) {
        LOG_CRIT("[k_mkfs] Failed to allocate memory for zero buffer.");
        close(fd);
        return PennFatErr_INTERNAL;
    }
    if (lseek(fd, fat_region_size, SEEK_SET) < 0) {
        LOG_CRIT("[k_mkfs] Failed to seek to root directory region.");
        free(zero_buf);
        close(fd);
        return PennFatErr_INTERNAL;
    }
    if (write(fd, zero_buf, block_size) != block_size) {
        LOG_CRIT("[k_mkfs] Failed to write root directory region.");
        free(zero_buf);
        close(fd);
        return PennFatErr_INTERNAL;
    }
    free(zero_buf);
    
    /* The data region can be left uninitialized or zeroed as needed. */

    LOG_INFO("[k_mkfs] Created filesystem '%s' with %d blocks in FAT and block size %u bytes.",
        fs_name, blocks_in_fat, block_size);

    close(fd);
    return PennFatErr_SUCCESS;
}
