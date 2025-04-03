#include "pennfat_kernel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* --- Definitions --- */

/* FAT entry definitions */
#define FAT_FREE  0x0000
#define FAT_EOC   0xFFFF  // End-Of-Chain

/* Table sizes */
#define MAX_SYSTEM_FILES 64
#define MAX_FD 32
#define MAX_DIR_ENTRIES 128

/* --- Data Structures --- */

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
typedef struct {
    bool     in_use;        // FD slot is active
    int      sysfile_index; // Index into system-wide file table
    int      mode;          // F_READ, F_WRITE, or F_APPEND
    uint32_t offset;        // Current file pointer offset
} fd_entry_t;
static fd_entry_t g_fd_table[MAX_FD];

/* Directory Entry Structure */
typedef struct {
    char     filename[32];  // Null-terminated filename
    uint16_t first_block;   // Starting block in FAT
    uint32_t size;          // File size in bytes
    uint16_t perms;         // Permissions (if implemented)
    time_t   mtime;         // Last modification time
} dir_entry_t;
static dir_entry_t g_root_dir[MAX_DIR_ENTRIES];

/* FAT Array (in memory) */
static uint16_t *g_fat = NULL;

/* Superblock Structure */
typedef struct {
    uint32_t magic;
    uint32_t block_size;       // Bytes per block
    uint32_t fat_start_block;  // Starting block of FAT region
    uint32_t fat_block_count;  // Number of blocks for FAT
    uint32_t root_start_block; // Starting block of root directory
    uint32_t root_block_count; // Number of blocks for directory
    uint32_t data_start_block; // Starting block of data region
} superblock_t;
static superblock_t g_superblock;

/* Global variables for host FS access and mounting */
static FILE *g_fs_fp = NULL;
static int   g_mounted = 0;
static uint32_t g_block_size = 512;  // Default; overwritten by superblock

/* --- Helper Routines --- */

/* read_block: Reads a block from the underlying FS */
static int read_block(void *buf, uint32_t block_index) {
    if (!g_fs_fp) return -1;
    if (fseek(g_fs_fp, block_index * g_block_size, SEEK_SET) != 0)
        return -1;
    if (fread(buf, 1, g_block_size, g_fs_fp) != g_block_size)
        return -1;
    return 0;
}

/* write_block: Writes a block to the underlying FS */
static int write_block(const void *buf, uint32_t block_index) {
    if (!g_fs_fp) return -1;
    if (fseek(g_fs_fp, block_index * g_block_size, SEEK_SET) != 0)
        return -1;
    if (fwrite(buf, 1, g_block_size, g_fs_fp) != g_block_size)
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

/* --- System-Wide File Table Helpers --- */

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

/* --- Kernel-Level API Implementations --- */

int k_open(const char *fname, int mode) {
    if (!g_mounted)
        return -1;
    int found_idx = -1, free_idx = -1;
    for (int i = 0; i < MAX_DIR_ENTRIES; i++) {
        if (g_root_dir[i].filename[0] == '\0') {
            if (free_idx < 0)
                free_idx = i;
        } else if (strncmp(g_root_dir[i].filename, fname, sizeof(g_root_dir[i].filename)) == 0) {
            found_idx = i;
            break;
        }
    }
    if (found_idx < 0) {
        if (mode == F_READ)
            return -1; /* Cannot open non-existent file for reading */
        if (free_idx < 0)
            return -1; /* No free directory entries */
        found_idx = free_idx;
        memset(&g_root_dir[found_idx], 0, sizeof(dir_entry_t));
        strncpy(g_root_dir[found_idx].filename, fname, sizeof(g_root_dir[found_idx].filename) - 1);
        g_root_dir[found_idx].filename[sizeof(g_root_dir[found_idx].filename) - 1] = '\0';
        g_root_dir[found_idx].size = 0;
        g_root_dir[found_idx].mtime = time(NULL);
        int new_blk = allocate_free_block();
        if (new_blk < 0)
            return -1;
        g_root_dir[found_idx].first_block = new_blk;
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
        }
    }
    int sys_idx = find_and_increment_sysfile(found_idx);
    if (sys_idx < 0) {
        sys_idx = create_sysfile_entry(found_idx);
        if (sys_idx < 0)
            return -1;
    }
    for (int fd = 0; fd < MAX_FD; fd++) {
        if (!g_fd_table[fd].in_use) {
            g_fd_table[fd].in_use = true;
            g_fd_table[fd].sysfile_index = sys_idx;
            g_fd_table[fd].mode = mode;
            g_fd_table[fd].offset = (mode == F_APPEND) ? g_sysfile_table[sys_idx].size : 0;
            return fd;
        }
    }
    release_sysfile_entry(sys_idx);
    return -1;
}

int k_read(int fd, int n, char *buf) {
    if (!g_mounted)
        return -1;
    if (fd < 0 || fd >= MAX_FD || !g_fd_table[fd].in_use)
        return -1;
    fd_entry_t *fdesc = &g_fd_table[fd];
    int sys_idx = fdesc->sysfile_index;
    system_file_t *sf = &g_sysfile_table[sys_idx];
    if (fdesc->mode == F_WRITE)
        return -1; /* Cannot read in write-only mode */
    uint32_t size_left = (sf->size > fdesc->offset) ? sf->size - fdesc->offset : 0;
    if (size_left == 0)
        return 0; /* EOF */
    int to_read = (n < (int)size_left) ? n : (int)size_left;
    int total_read = 0;
    char *block_buf = malloc(g_block_size);
    if (!block_buf)
        return -1;
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

int k_write(int fd, const char *buf, int n) {
    if (!g_mounted)
        return -1;
    if (fd < 0 || fd >= MAX_FD || !g_fd_table[fd].in_use)
        return -1;
    fd_entry_t *fdesc = &g_fd_table[fd];
    int sys_idx = fdesc->sysfile_index;
    system_file_t *sf = &g_sysfile_table[sys_idx];
    if (fdesc->mode == F_READ)
        return -1; /* Cannot write in read-only mode */
    int total_written = 0;
    char *block_buf = malloc(g_block_size);
    if (!block_buf)
        return -1;
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
    free(block_buf);
    return total_written;
}

int k_close(int fd) {
    if (!g_mounted)
        return -1;
    if (fd < 0 || fd >= MAX_FD || !g_fd_table[fd].in_use)
        return -1;
    fd_entry_t *fdesc = &g_fd_table[fd];
    int sys_idx = fdesc->sysfile_index;
    fdesc->in_use = false;
    release_sysfile_entry(sys_idx);
    return 0;
}

int k_unlink(const char *fname) {
    if (!g_mounted)
        return -1;
    int dir_index = -1;
    for (int i = 0; i < MAX_DIR_ENTRIES; i++) {
        if (strncmp(g_root_dir[i].filename, fname, sizeof(g_root_dir[i].filename)) == 0) {
            dir_index = i;
            break;
        }
    }
    if (dir_index < 0)
        return -1;
    for (int i = 0; i < MAX_SYSTEM_FILES; i++) {
        if (g_sysfile_table[i].in_use && g_sysfile_table[i].dir_index == dir_index)
            return -1; /* File is open */
    }
    uint16_t cur = g_root_dir[dir_index].first_block;
    while (cur != FAT_EOC) {
        uint16_t nxt = g_fat[cur];
        g_fat[cur] = FAT_FREE;
        cur = nxt;
    }
    memset(&g_root_dir[dir_index], 0, sizeof(dir_entry_t));
    return 0;
}

int k_lseek(int fd, int offset, int whence) {
    if (!g_mounted)
        return -1;
    if (fd < 0 || fd >= MAX_FD || !g_fd_table[fd].in_use)
        return -1;
    fd_entry_t *fdesc = &g_fd_table[fd];
    int sys_idx = fdesc->sysfile_index;
    system_file_t *sf = &g_sysfile_table[sys_idx];
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
            return -1;
    }
    if (new_offset < 0)
        return -1;
    fdesc->offset = (uint32_t)new_offset;
    return fdesc->offset;
}

int k_ls(const char *fname) {
    if (!g_mounted)
        return -1;
    if (fname && fname[0] != '\0') {
        for (int i = 0; i < MAX_DIR_ENTRIES; i++) {
            if (strncmp(g_root_dir[i].filename, fname, sizeof(g_root_dir[i].filename)) == 0) {
                printf("%5u %10u %s\n", g_root_dir[i].first_block, g_root_dir[i].size, g_root_dir[i].filename);
                return 0;
            }
        }
        return -1;
    } else {
        for (int i = 0; i < MAX_DIR_ENTRIES; i++) {
            if (g_root_dir[i].filename[0] != '\0')
                printf("%5u %10u %s\n", g_root_dir[i].first_block, g_root_dir[i].size, g_root_dir[i].filename);
        }
        return 0;
    }
}

/* --- Mount/Unmount Functions --- */

int mount_fs(const char *fs_name) {
    if (g_mounted) {
        fprintf(stderr, "Filesystem already mounted.\n");
        return -1;
    }
    g_fs_fp = fopen(fs_name, "rb+");
    if (!g_fs_fp) {
        perror("fopen");
        return -1;
    }
    if (fread(&g_superblock, sizeof(superblock_t), 1, g_fs_fp) != 1) {
        fclose(g_fs_fp);
        g_fs_fp = NULL;
        return -1;
    }
    g_block_size = g_superblock.block_size;
    uint32_t fat_bytes = g_superblock.fat_block_count * g_block_size;
    g_fat = (uint16_t *)malloc(fat_bytes);
    if (!g_fat) {
        fclose(g_fs_fp);
        return -1;
    }
    if (fseek(g_fs_fp, g_superblock.fat_start_block * g_block_size, SEEK_SET) != 0) {
        free(g_fat);
        fclose(g_fs_fp);
        return -1;
    }
    if (fread(g_fat, 1, fat_bytes, g_fs_fp) != fat_bytes) {
        free(g_fat);
        fclose(g_fs_fp);
        return -1;
    }
    uint32_t root_bytes = g_superblock.root_block_count * g_block_size;
    if (fseek(g_fs_fp, g_superblock.root_start_block * g_block_size, SEEK_SET) != 0) {
        free(g_fat);
        fclose(g_fs_fp);
        return -1;
    }
    if (fread(g_root_dir, 1, root_bytes, g_fs_fp) != root_bytes) {
        free(g_fat);
        fclose(g_fs_fp);
        return -1;
    }
    memset(g_sysfile_table, 0, sizeof(g_sysfile_table));
    memset(g_fd_table, 0, sizeof(g_fd_table));
    g_mounted = 1;
    return 0;
}

int unmount_fs(void) {
    if (!g_mounted) {
        fprintf(stderr, "No filesystem is mounted.\n");
        return -1;
    }
    uint32_t fat_bytes = g_superblock.fat_block_count * g_block_size;
    if (fseek(g_fs_fp, g_superblock.fat_start_block * g_block_size, SEEK_SET) != 0)
        return -1;
    if (fwrite(g_fat, 1, fat_bytes, g_fs_fp) != fat_bytes)
        return -1;
    uint32_t root_bytes = g_superblock.root_block_count * g_block_size;
    if (fseek(g_fs_fp, g_superblock.root_start_block * g_block_size, SEEK_SET) != 0)
        return -1;
    if (fwrite(g_root_dir, 1, root_bytes, g_fs_fp) != root_bytes)
        return -1;
    if (fseek(g_fs_fp, 0, SEEK_SET) != 0)
        return -1;
    if (fwrite(&g_superblock, sizeof(superblock_t), 1, g_fs_fp) != 1)
        return -1;
    fclose(g_fs_fp);
    g_fs_fp = NULL;
    free(g_fat);
    g_fat = NULL;
    g_mounted = 0;
    return 0;
}
