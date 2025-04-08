#ifndef PENNFAT_DEFINITIONS_H
#define PENNFAT_DEFINITIONS_H

#include <stdint.h>
#include <time.h>

/* PennFAT directory entry: fixed 64 bytes */
typedef struct {
    char     name[32];     // 32-byte null-terminated file name.
                           // Special markers: 0 = end of directory, 1 = deleted, 2 = deleted but in use.
    uint32_t size;         // 4 bytes: file size in bytes.
    uint16_t first_block;   // 2 bytes: first block number (undefined if size is zero).
    uint8_t  type;         // 1 byte: file type (0: unknown, 1: regular, 2: directory, 4: symbolic link).
    uint8_t  perm;         // 1 byte: permissions (0, 2, 4, 5, 6, or 7).
    time_t   mtime;        // 8 bytes: creation/modification time.
    char     reserved[16]; // 16 bytes reserved.
} __attribute__((packed)) dir_entry_t;  // Ensure no padding
static dir_entry_t *g_root_dir;

/* File Descriptor Table Entry */
typedef struct {
    bool     in_use;        // FD slot is active
    int      sysfile_index; // Index into system-wide file table
    int      mode;          // F_READ, F_WRITE, or F_APPEND
    uint32_t offset;        // Current file pointer offset
} fd_entry_t;

#endif /* PENNFAT_DEFINITIONS_H */