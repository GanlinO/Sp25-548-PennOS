#ifndef PENNFAT_DEFINITIONS_H
#define PENNFAT_DEFINITIONS_H

#include <stdint.h>
#include <time.h>

/* File Modes */
#define K_O_CREATE   0x1
#define K_O_RDONLY     0x2
#define K_O_WRONLY    0x4
#define K_O_APPEND   0x8
#define K_O_TRUNC    0x10

#define HAS_CREATE(mode)  (((mode) & K_O_CREATE) != 0)
#define HAS_READ(mode)    (((mode) & K_O_RDONLY) != 0)
#define HAS_WRITE(mode)   (((mode) & K_O_WRONLY) != 0)
#define HAS_APPEND(mode)  (((mode) & K_O_APPEND) != 0)

static inline int is_valid_mode(int mode) {
    // 1) Disallow any bits outside our four known flags
    if (mode & ~(K_O_CREATE | K_O_RDONLY | K_O_WRONLY | K_O_APPEND)) {
        return 0; // invalid bits set
    }

    // 2) Forbid using both WRITE and APPEND together
    if ((mode & K_O_WRONLY) && (mode & K_O_APPEND)) {
        return 0;
    }

    return 1;
}

/* lseek Whence Constants */
#define F_SEEK_SET 0
#define F_SEEK_CUR 1
#define F_SEEK_END 2

/* Permission bit definitions */

/* Combined permission examples:
   - read and executable: PERM_READ | PERM_EXEC = 0x4 | 0x1 = 5
   - read and write: PERM_READ | PERM_WRITE = 0x4 | 0x2 = 6
   - read, write, and executable: 7 */
#define PERM_NONE   0x0
#define PERM_EXEC   0x1
#define PERM_WRITE  0x2
#define PERM_READ   0x4

#define DEF_PERM  (PERM_READ | PERM_WRITE)  // Default permissions

#define CAN_READ(perm)  (((perm) & PERM_READ) != 0)
#define CAN_WRITE(perm) (((perm) & PERM_WRITE) != 0)
#define CAN_EXEC(perm)  (((perm) & PERM_EXEC) != 0)

#define REQ_READ_PERM(mode)  (((mode) & K_O_RDONLY) != 0)
#define REQ_WRITE_PERM(mode) (((mode) & (K_O_WRONLY | K_O_APPEND)) != 0)

#define VALID_PERM(perm) ((perm) == PERM_NONE || (perm) == PERM_EXEC || \
                         (perm) == PERM_WRITE || (perm) == (PERM_READ | PERM_EXEC) || \
                         (perm) == (PERM_READ | PERM_WRITE) || \
                         (perm) == (PERM_READ | PERM_WRITE | PERM_EXEC))

/* PennFAT directory entry: fixed 64 bytes */
typedef struct {
    char     name[32];     // 32-byte null-terminated file name.
                           // Special markers: 0 = end of directory, 1 = deleted, 2 = deleted but in use.
    uint32_t size;         // 4 bytes: file size in bytes.
    uint16_t first_block;  // 2 bytes: first block number (undefined if size is zero).
    uint8_t  type;         // 1 byte: file type (0: unknown, 1: regular, 2: directory, 4: symbolic link).
    uint8_t  perm;         // 1 byte: permissions (0, 2, 4, 5, 6, or 7).
    time_t   mtime;        // 8 bytes: creation/modification time.
    char     reserved[16]; // 16 bytes reserved.
} __attribute__((packed)) dir_entry_t;  // Ensure no padding

/* File Descriptor Table Entry */
typedef struct {
    int      in_use;        // FD slot is active
    int      sysfile_index; // Index into system-wide file table
    int      mode;          // F_READ, F_WRITE, or F_APPEND
    uint32_t offset;        // Current file pointer offset
} fd_entry_t;

/* System-Wide File Table Entry */
typedef struct {
    int      ref_count;   // Number of FDs referencing this file
    int      in_use;      // Whether this entry is active
    uint16_t first_block; // Starting block (from directory)
    uint32_t size;        // File size in bytes
    time_t   mtime;       // Last modification time
    int      dir_index;   // Index in the directory array
} system_file_t;

#endif /* PENNFAT_DEFINITIONS_H */