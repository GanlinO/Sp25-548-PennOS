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
/* 1 if a filesystem is mounted; 0 otherwise */
static int g_mounted = 0;  // put it here for cleanup reference

/* Static logger pointer for this module */
static Logger *logger = NULL;

/* Initialization function: call this from your main application */
void pennfat_kernel_init(void) {
    LOGGER_INIT("pennfat_kernel", LOG_LEVEL_INFO);
}

/* Cleanup function: call this during application shutdown */
void pennfat_kernel_cleanup(void) {
    LOGGER_CLOSE();

    if (g_mounted) {
        k_unmount();
    }
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
// 2) GLOBAL DATA STRUCTURES
// ---------------------------------------------------------------------------

// static int g_mounted = 0;            // 1 if a filesystem is mounted; 0 otherwise
static int g_fs_fd = -1;                // File descriptor for the FS image
static uint32_t g_block_size = 512;     // Actual block size (set during mount)
static uint16_t *g_fat = NULL;          // Pointer to the mapped FAT region
static dir_entry_t *g_root_dir = NULL;  // Pointer to the root directory block (1 block)


/* The superblock info is embedded in FAT[0]:
 * MSB = number of FAT blocks; LSB = block_size_config.
 * For helper routines we store parsed info here:
 */
 typedef struct {
    uint32_t fat_block_count;  /* number of FAT blocks (from FAT[0]'s MSB) */
    uint32_t data_start_block; /* computed: FAT region size in blocks */
} superblock_t;
static superblock_t g_superblock;

/* Global arrays for our system-wide file table and FD table */
static system_file_t g_sysfile_table[MAX_SYSTEM_FILES];
static fd_entry_t g_fd_table[MAX_FD];

/* Current working directory block - starts at root (block 1) */
static uint16_t g_cwd_block = 1;

/* Maximum path depth for directory traversal */
#define MAX_DEPTH 32
#define PATH_MAX 256

/* We'll use a simpler approach without a block cache */

/* Path resolution result structure */
typedef struct {
    bool found;           // Whether the path was found
    bool is_root;         // Whether this is the root directory
    dir_entry_t entry;    // The directory entry if found
    uint16_t entry_block; // Block containing the entry
    int entry_index_in_block; // Index of entry within the block
    uint16_t parent_dir_block; // Block of parent directory
} resolved_path_t;


// ---------------------------------------------------------------------------
// 3) HELPER ROUTINES
// ---------------------------------------------------------------------------

// Helper to get the filename component from a path
static const char* get_filename_from_path(const char *path) {
    if (!path) return NULL;
    char *last_slash = strrchr(path, '/');
    return last_slash ? last_slash + 1 : path;
}

// We'll use a simpler approach without a block cache

static inline void perm_to_str(uint8_t perm, char *str) {
    str[0] = (perm & PERM_READ)  ? 'r' : '-';
    str[1] = (perm & PERM_WRITE) ? 'w' : '-';
    str[2] = (perm & PERM_EXEC)  ? 'x' : '-';
    str[3] = '\0';
}

/* 
 * read_block: Reads a block from the FS image using g_fs_fd.
 * Calculates offset = block_index * g_block_size.
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
 * write_block: Writes a block to the FS image using g_fs_fd.
 * Computes offset = block_index * g_block_size.
 * Always flushes to disk to ensure data integrity.
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
    
    // Always flush to disk immediately to ensure data integrity
    if (fdatasync(g_fs_fd) < 0) {
        LOG_ERR("[write_block] Failed to sync block %u to disk: %s", block_index, strerror(errno));
        return -1;
    }

    return 0;
}

// Helper to read the target of a symbolic link
static PennFatErr read_symlink_target(const dir_entry_t *link_entry, char *target_buf, size_t buf_size) {
    if (!link_entry || !target_buf || buf_size == 0) return PennFatErr_INVAD;
    if (link_entry->type != 4) {
        LOG_ERR("[read_symlink_target] Entry is not a symlink (type=%d)", link_entry->type);
        return PennFatErr_INVAD; // Not a symlink
    }

    LOG_DEBUG("[read_symlink_target] Reading symlink target: first_block=%u, size=%u",
              link_entry->first_block, link_entry->size);

    // Read the block containing the target path
    char *block_buffer = malloc(g_block_size);
    if (!block_buffer) {
        LOG_ERR("[read_symlink_target] Failed to allocate memory for block buffer");
        return PennFatErr_OUTOFMEM;
    }

    if (read_block(block_buffer, link_entry->first_block) != 0) {
        LOG_ERR("[read_symlink_target] Failed to read block %u", link_entry->first_block);
        free(block_buffer);
        return PennFatErr_IO;
    }

    // Copy the target path to the buffer, ensuring it's null-terminated
    size_t target_len = link_entry->size;
    if (target_len >= buf_size) {
        LOG_WARN("[read_symlink_target] Target path truncated from %zu to %zu bytes",
                 target_len, buf_size - 1);
        target_len = buf_size - 1;
    }

    memcpy(target_buf, block_buffer, target_len);
    target_buf[target_len] = '\0';

    LOG_DEBUG("[read_symlink_target] Read symlink target: '%s'", target_buf);

    free(block_buffer);
    return PennFatErr_OK;
}

/*
 * locate_block_in_chain: Given a file offset, finds the physical block and the
 * offset within that block, by walking the FAT chain starting at start_block.
 */
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

/*
 * allocate_free_block: Scans the FAT (from data_start_block onward) to find a free block,
 * marks it as allocated (FAT_EOC), and returns its index. Returns -1 if no free block.
 */
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

/*
 * free_block_chain: Frees all blocks in a chain starting from start_block.
 * Sets all FAT entries in the chain to FAT_FREE.
 */
static PennFatErr free_block_chain(uint16_t start_block) {
    if (start_block == FAT_FREE || start_block == FAT_EOC) {
        return PennFatErr_OK; // Nothing to free
    }

    uint16_t current = start_block;
    uint16_t next;

    while (current != FAT_EOC && current != FAT_FREE) {
        next = g_fat[current];
        g_fat[current] = FAT_FREE;
        current = next;
    }

    return PennFatErr_OK;
}

/*
 * read_dirent: Reads a directory entry from a specific block and index.
 */
static PennFatErr read_dirent(uint16_t block_num, int index, dir_entry_t *entry) {
    if (!entry) return PennFatErr_INVAD;
    if (block_num == FAT_FREE || block_num == FAT_EOC) return PennFatErr_INVAD;

    char *block_buffer = malloc(g_block_size);
    if (!block_buffer) return PennFatErr_OUTOFMEM;

    if (read_block(block_buffer, block_num) != 0) {
        free(block_buffer);
        return PennFatErr_IO;
    }

    dir_entry_t *dir_entries = (dir_entry_t *)block_buffer;
    uint32_t entries_per_block = g_block_size / sizeof(dir_entry_t);

    if (index < 0 || (uint32_t)index >= entries_per_block) {
        free(block_buffer);
        return PennFatErr_INVAD;
    }

    memcpy(entry, &dir_entries[index], sizeof(dir_entry_t));
    free(block_buffer);
    return PennFatErr_OK;
}

/*
 * write_dirent: Writes a directory entry to a specific block and index.
 */
static PennFatErr write_dirent(uint16_t block_num, int index, const dir_entry_t *entry) {
    if (!entry) return PennFatErr_INVAD;
    if (block_num == FAT_FREE || block_num == FAT_EOC) return PennFatErr_INVAD;

    char *block_buffer = malloc(g_block_size);
    if (!block_buffer) return PennFatErr_OUTOFMEM;

    if (read_block(block_buffer, block_num) != 0) {
        free(block_buffer);
        return PennFatErr_IO;
    }

    dir_entry_t *dir_entries = (dir_entry_t *)block_buffer;
    uint32_t entries_per_block = g_block_size / sizeof(dir_entry_t);

    if (index < 0 || (uint32_t)index >= entries_per_block) {
        free(block_buffer);
        return PennFatErr_INVAD;
    }

    memcpy(&dir_entries[index], entry, sizeof(dir_entry_t));

    // Log the directory entry being written
    LOG_DEBUG("[write_dirent] Writing directory entry '%s' to block %u index %d",
              entry->name, block_num, index);

    // Force the block to be written to disk immediately for directory blocks
    if (write_block(block_buffer, block_num) != 0) {
        free(block_buffer);
        return PennFatErr_IO;
    }

    // The write_block function already flushes to disk

    free(block_buffer);
    return PennFatErr_OK;
}

/* 
 * lookup_entry:
 *   Searches the global directory (g_root_dir) for an entry with a matching file name.
 *   If not found and create==true, it creates a new entry.
 * Returns the directory index on success or a negative PennFatErr code on failure.
 */
 static int __attribute__((unused)) lookup_entry(const char *fname, int mode) {
    if (!fname || fname[0] == '\0') {
        LOG_ERR("[lookup_entry] Invalid filename.");
        return PennFatErr_INVAD;
    }

    if (!g_mounted) {
        LOG_WARN("[lookup_entry] Failed to lookup file '%s': Filesystem not mounted.", fname);
        return PennFatErr_NOT_MOUNTED;
    }

    /* Compute the actual number of directory entries available in the allocated block:
       Since g_root_dir points to one block, 
         num_entries = g_block_size / sizeof(dir_entry_t)
    */
    uint32_t num_entries = g_block_size / sizeof(dir_entry_t);
    
    int free_idx = -1;
    for (int i = 0; i < num_entries; i++) {
        if (g_root_dir[i].name[0] == '\0') {
            if (free_idx < 0) {
                LOG_DEBUG("[lookup_entry] Found free directory entry at index %d for file '%s'.", i, fname);
                free_idx = i;
            }
        } else if (strncmp(g_root_dir[i].name, fname, sizeof(g_root_dir[i].name)) == 0) {
            LOG_DEBUG("[lookup_entry] Found existing file entry at index %d for file '%s'.", i, fname);

            /* Found a matching entry.
               Now check permission based on op_mode:
                 - If op_mode == F_READ: require PERM_READ.
                 - If op_mode == F_WRITE or F_APPEND: require PERM_WRITE.
            */
            if ((REQ_READ_PERM(mode) && !CAN_READ(g_root_dir[i].perm)) ||
                (REQ_WRITE_PERM(mode) && !CAN_WRITE(g_root_dir[i].perm))) {
                LOG_ERR("[lookup_entry] Permission denied for file '%s'.", fname);
                return PennFatErr_PERM;
            }
            return i;  // Found the file entry
        }
    }
    
    if (!HAS_CREATE(mode)) {
        LOG_INFO("[lookup_entry] Failed to lookup file '%s': File does not exist.", fname);
        return PennFatErr_EXISTS;  // Not found and not allowed to create
    }

    if (free_idx < 0) {
        LOG_ERR("[lookup_entry] Failed to lookup file '%s': No free directory entries available for new file.", fname);
        return PennFatErr_OUTOFMEM;  // No free directory entries available
    }
    
    /* Create a new directory entry */
    int idx = free_idx;
    memset(&g_root_dir[idx], 0, sizeof(dir_entry_t));
    strncpy(g_root_dir[idx].name, fname, sizeof(g_root_dir[idx].name) - 1);
    g_root_dir[idx].size = 0;
    g_root_dir[idx].mtime = time(NULL);
    g_root_dir[idx].perm = DEF_PERM;  // Default permissions
    
    /* Allocate first block for the new file */
    int block = allocate_free_block();
    if (block < 0) {
        LOG_ERR("[lookup_entry] Failed to allocate a new block for file '%s': No free blocks available.", fname);
        memset(&g_root_dir[idx], 0, sizeof(dir_entry_t));  // Clear the entry
        return PennFatErr_NOSPACE;  // No free blocks available
    }
    g_root_dir[idx].first_block = (uint16_t)block;

    LOG_DEBUG("[lookup_entry] Created new file entry for '%s' at index %d with starting block %u.", 
              fname, idx, g_root_dir[idx].first_block);

    return idx;
}


// ---------------------------------------------------------------------------
// 3) SYSTEM-WIDE FILE TABLE (SWFT) HELPERS
// ---------------------------------------------------------------------------

/* find_and_increment_sysfile: If the file is already open, increment its ref count */
static int find_and_increment_sysfile(int pseudo_inode) { // Takes pseudo-inode
    for (int i = 0; i < MAX_SYSTEM_FILES; i++) {
        if (g_sysfile_table[i].in_use && g_sysfile_table[i].dir_index == pseudo_inode) { // Compare pseudo-inode
            g_sysfile_table[i].ref_count++;
            LOG_DEBUG("[find_and_increment_sysfile] Found existing SWFT entry %d for pseudo-inode 0x%x, ref count %d.",
                      i, pseudo_inode, g_sysfile_table[i].ref_count);
            return i;
        }
    }
    return -1;
}

/* Create SWFT entry using resolved path info */
static int create_sysfile_entry_from_resolved(const resolved_path_t *resolved, int pseudo_inode) {
    for (int i = 0; i < MAX_SYSTEM_FILES; i++) {
        if (!g_sysfile_table[i].in_use) {
            g_sysfile_table[i].in_use = true;
            g_sysfile_table[i].ref_count = 1;
            g_sysfile_table[i].dir_index = pseudo_inode; // Store pseudo-inode
            g_sysfile_table[i].first_block = resolved->entry.first_block;
            g_sysfile_table[i].size = resolved->entry.size;
            g_sysfile_table[i].mtime = resolved->entry.mtime;
            // Store other relevant info if needed (e.g., permissions?)

            LOG_DEBUG("[create_sysfile_entry] Created new SWFT entry %d for pseudo-inode 0x%x (block %u, size %u).",
                      i, pseudo_inode, resolved->entry.first_block, resolved->entry.size);
            return i;
        }
    }
    return -1; // No free SWFT entries
}


/* release_sysfile_entry: Decrement ref count and free if it reaches zero */
static void release_sysfile_entry(int sys_idx) {
    if (sys_idx < 0 || sys_idx >= MAX_SYSTEM_FILES || !g_sysfile_table[sys_idx].in_use) {
        return;
    }

    g_sysfile_table[sys_idx].ref_count--;
    LOG_DEBUG("[release_sysfile_entry] Decremented ref count for SWFT entry %d to %d.", sys_idx, g_sysfile_table[sys_idx].ref_count);

    if (g_sysfile_table[sys_idx].ref_count <= 0) {
         // Entry is no longer referenced by any FD. Update the directory entry on disk.
         int pseudo_inode = g_sysfile_table[sys_idx].dir_index;
         uint16_t entry_block = (pseudo_inode >> 16) & 0xFFFF;
         int entry_index = pseudo_inode & 0xFFFF;

         dir_entry_t current_entry;
         PennFatErr err = read_dirent(entry_block, entry_index, &current_entry);
         if (err == PennFatErr_OK) {
             // Only update if the entry hasn't been deleted/changed underneath us
             LOG_DEBUG("[release_sysfile_entry] Checking dirent update condition for SWFT %d (pseudo-inode 0x%x).", sys_idx, pseudo_inode);
             LOG_DEBUG("[release_sysfile_entry] Disk dirent: name[0]=%d, first_block=%u. SWFT: first_block=%u", (int)current_entry.name[0], current_entry.first_block, g_sysfile_table[sys_idx].first_block);
             if (current_entry.name[0] != 0 && (uint8_t)current_entry.name[0] != 1 && (uint8_t)current_entry.name[0] != 2 &&
                 current_entry.first_block == g_sysfile_table[sys_idx].first_block) // Basic check
             {
                 LOG_DEBUG("[release_sysfile_entry] Dirent update condition met. Updating disk dirent for SWFT %d.", sys_idx);
                 current_entry.size = g_sysfile_table[sys_idx].size;
                 current_entry.mtime = g_sysfile_table[sys_idx].mtime;
                 // first_block might change during writes, update it too
                 current_entry.first_block = g_sysfile_table[sys_idx].first_block;

                 err = write_dirent(entry_block, entry_index, &current_entry);
                 if (err != PennFatErr_OK) {
                     LOG_ERR("[release_sysfile_entry] Failed to write updated dirent for SWFT %d (pseudo-inode 0x%x) on close (Error %d).",
                              sys_idx, pseudo_inode, err);
                 } else {
                      LOG_DEBUG("[release_sysfile_entry] Updated dirent on disk for SWFT %d (pseudo-inode 0x%x) on close.", sys_idx, pseudo_inode);
                 }
             } else {
                  LOG_WARN("[release_sysfile_entry] Dirent for SWFT %d (pseudo-inode 0x%x) seems changed/deleted; skipping disk update on close.", sys_idx, pseudo_inode);
             }
         } else {
              LOG_ERR("[release_sysfile_entry] Failed to read dirent for SWFT %d (pseudo-inode 0x%x) on close (Error %d). Cannot update disk.",
                      sys_idx, pseudo_inode, err);
         }


        // Clear the SWFT entry
        memset(&g_sysfile_table[sys_idx], 0, sizeof(system_file_t));
        LOG_DEBUG("[release_sysfile_entry] Released SWFT entry %d.", sys_idx);
    }
}

/*
 * add_dirent_to_dir: Adds a directory entry to a directory block.
 * Finds the first available slot in the directory and adds the entry there.
 */
static PennFatErr add_dirent_to_dir(uint16_t dir_block, const dir_entry_t *entry) {
    if (!entry) return PennFatErr_INVAD;
    if (dir_block == FAT_FREE || dir_block == FAT_EOC) return PennFatErr_INVAD;

    char *block_buffer = malloc(g_block_size);
    if (!block_buffer) return PennFatErr_OUTOFMEM;

    uint16_t current_block = dir_block;
    dir_entry_t *dir_entries;
    uint32_t entries_per_block = g_block_size / sizeof(dir_entry_t);
    bool found_slot = false;
    uint16_t slot_block = 0;
    int slot_index = -1;

    // Search for an available slot in the directory chain
    while (current_block != FAT_EOC && current_block != FAT_FREE) {
        if (read_block(block_buffer, current_block) != 0) {
            free(block_buffer);
            return PennFatErr_IO;
        }

        dir_entries = (dir_entry_t *)block_buffer;

        // Look for a free slot (empty or deleted entry)
        for (uint32_t i = 0; i < entries_per_block; i++) {
            if (dir_entries[i].name[0] == 0 || (uint8_t)dir_entries[i].name[0] == 1) {
                // Found a free slot
                found_slot = true;
                slot_block = current_block;
                slot_index = i;
                break;
            }
        }

        if (found_slot) break;

        // Move to the next block in the directory chain
        current_block = g_fat[current_block];
    }

    // If no slot found, allocate a new block for the directory
    if (!found_slot) {
        int new_block = allocate_free_block();
        if (new_block < 0) {
            free(block_buffer);
            return PennFatErr_NOSPACE;
        }

        // Find the last block in the directory chain
        current_block = dir_block;
        while (g_fat[current_block] != FAT_EOC) {
            current_block = g_fat[current_block];
        }

        // Link the new block to the chain
        g_fat[current_block] = (uint16_t)new_block;

        // Clear the new block
        memset(block_buffer, 0, g_block_size);
        if (write_block(block_buffer, new_block) != 0) {
            g_fat[current_block] = FAT_EOC; // Rollback
            g_fat[new_block] = FAT_FREE;    // Free the allocated block
            free(block_buffer);
            return PennFatErr_IO;
        }

        slot_block = (uint16_t)new_block;
        slot_index = 0;
    }

    // Write the entry to the found/allocated slot
    if (read_block(block_buffer, slot_block) != 0) {
        free(block_buffer);
        return PennFatErr_IO;
    }

    dir_entries = (dir_entry_t *)block_buffer;
    memcpy(&dir_entries[slot_index], entry, sizeof(dir_entry_t));

    if (write_block(block_buffer, slot_block) != 0) {
        free(block_buffer);
        return PennFatErr_IO;
    }

    free(block_buffer);
    return PennFatErr_OK;
}

/*
 * find_entry_in_dir: Searches for an entry with the given name in a directory.
 * If found, fills the resolved structure with the entry details.
 */
static PennFatErr find_entry_in_dir(uint16_t dir_block, const char *name, resolved_path_t *resolved) {
    if (!name || !resolved) return PennFatErr_INVAD;
    if (dir_block == FAT_FREE || dir_block == FAT_EOC) return PennFatErr_INVAD;

    char *block_buffer = malloc(g_block_size);
    if (!block_buffer) return PennFatErr_OUTOFMEM;

    uint16_t current_block = dir_block;
    dir_entry_t *dir_entries;
    uint32_t entries_per_block = g_block_size / sizeof(dir_entry_t);
    bool found = false;

    // Initialize resolved structure
    resolved->found = false;
    resolved->is_root = false;
    resolved->parent_dir_block = dir_block;

    // Search for the entry in the directory chain
    while (current_block != FAT_EOC && current_block != FAT_FREE) {
        if (read_block(block_buffer, current_block) != 0) {
            free(block_buffer);
            return PennFatErr_IO;
        }

        dir_entries = (dir_entry_t *)block_buffer;

        // Look for the entry with matching name
        for (uint32_t i = 0; i < entries_per_block; i++) {
            if (dir_entries[i].name[0] == 0) {
                // End of directory
                break;
            }

            if ((uint8_t)dir_entries[i].name[0] == 1 || (uint8_t)dir_entries[i].name[0] == 2) {
                // Deleted entry, skip
                continue;
            }

            if (strcmp(dir_entries[i].name, name) == 0) {
                // Found the entry
                found = true;
                resolved->found = true;
                resolved->entry_block = current_block;
                resolved->entry_index_in_block = i;
                memcpy(&resolved->entry, &dir_entries[i], sizeof(dir_entry_t));
                break;
            }
        }

        if (found) break;

        // Move to the next block in the directory chain
        current_block = g_fat[current_block];
    }

    free(block_buffer);
    return PennFatErr_OK;
}

/*
 * resolve_path: Resolves a path to a directory entry.
 * Handles absolute and relative paths, as well as '.' and '..' components.
 * If follow_symlinks is true, symbolic links in the path will be followed.
 */
static PennFatErr resolve_path_internal(const char *path, resolved_path_t *resolved, bool follow_symlinks, int symlink_depth) {
    // Prevent infinite symlink loops with a maximum depth
    if (symlink_depth > 8) { // Maximum symlink recursion depth
        LOG_ERR("[resolve_path] Maximum symlink recursion depth exceeded for path '%s'", path);
        return PennFatErr_RANGE;
    }
    if (!path || !resolved) return PennFatErr_INVAD;

    // Initialize resolved structure
    memset(resolved, 0, sizeof(resolved_path_t));
    resolved->found = false;
    resolved->is_root = false;

    // Handle empty path
    if (path[0] == '\0') {
        // Empty path refers to current directory
        resolved->found = true;
        resolved->is_root = (g_cwd_block == 1);
        resolved->entry_block = g_cwd_block;
        resolved->entry_index_in_block = -1; // Not applicable for directories
        resolved->parent_dir_block = g_cwd_block; // Parent is itself for empty path

        // Read the directory entry for the current directory
        if (g_cwd_block == 1) {
            // Root directory is special
            memset(&resolved->entry, 0, sizeof(dir_entry_t));
            strcpy(resolved->entry.name, "/");
            resolved->entry.type = 2; // Directory
            resolved->entry.perm = DEF_PERM;
            resolved->entry.first_block = 1;
            resolved->entry.mtime = time(NULL);
        } else {
            // For non-root directories, we need to find the entry in the parent
            // This is complex and requires traversing up the hierarchy
            // For now, just set basic info
            memset(&resolved->entry, 0, sizeof(dir_entry_t));
            strcpy(resolved->entry.name, ".");
            resolved->entry.type = 2; // Directory
            resolved->entry.perm = DEF_PERM;
            resolved->entry.first_block = g_cwd_block;
        }

        return PennFatErr_OK;
    }

    // Determine if this is an absolute or relative path
    uint16_t current_dir;
    if (path[0] == '/') {
        // Absolute path, start from root
        current_dir = 1; // Root directory is always block 1
        path++; // Skip the leading '/'
    } else {
        // Relative path, start from current directory
        current_dir = g_cwd_block;
    }

    // Handle root directory special case
    if (path[0] == '\0') {
        resolved->found = true;
        resolved->is_root = true;
        resolved->entry_block = 1; // Root directory
        resolved->entry_index_in_block = -1; // Not applicable for directories
        resolved->parent_dir_block = 1; // Parent of root is root

        // Set up root directory entry
        memset(&resolved->entry, 0, sizeof(dir_entry_t));
        strcpy(resolved->entry.name, "/");
        resolved->entry.type = 2; // Directory
        resolved->entry.perm = DEF_PERM;
        resolved->entry.first_block = 1;
        resolved->entry.mtime = time(NULL);

        return PennFatErr_OK;
    }

    // Parse the path components
    char path_copy[PATH_MAX];
    strncpy(path_copy, path, PATH_MAX - 1);
    path_copy[PATH_MAX - 1] = '\0';

    char *component = strtok(path_copy, "/");
    uint16_t parent_dir = current_dir;

    while (component != NULL) {
        // Handle '.' and '..' special cases
        if (strcmp(component, ".") == 0) {
            // Current directory, no change
            component = strtok(NULL, "/");
            continue;
        } else if (strcmp(component, "..") == 0) {
            // Parent directory
            if (current_dir == 1) {
                // Root has no parent, stay at root
                component = strtok(NULL, "/");
                continue;
            }

            // Find the '..' entry in the current directory to get the parent
            resolved_path_t dotdot_resolved;
            PennFatErr err = find_entry_in_dir(current_dir, "..", &dotdot_resolved);
            if (err != PennFatErr_OK || !dotdot_resolved.found) {
                return err; // Error finding parent directory
            }

            parent_dir = current_dir;
            current_dir = dotdot_resolved.entry.first_block;
            component = strtok(NULL, "/");
            continue;
        }

        // Regular component, look it up in the current directory
        parent_dir = current_dir;
        resolved_path_t component_resolved;
        PennFatErr err = find_entry_in_dir(current_dir, component, &component_resolved);
        if (err != PennFatErr_OK) {
            return err; // Error during lookup
        }

        if (!component_resolved.found) {
            // Component not found, path doesn't exist
            // But we can still return the parent directory info for creation
            resolved->found = false;
            resolved->parent_dir_block = current_dir;
            return PennFatErr_OK;
        }

        // Check if this is the last component
        char *next_component = strtok(NULL, "/");
        if (next_component == NULL) {
            // Last component, check if it's a symlink that needs to be followed
            if (follow_symlinks && component_resolved.entry.type == 4) { // Symbolic link
                // Read the target path
                char target_path[PATH_MAX];
                PennFatErr err = read_symlink_target(&component_resolved.entry, target_path, sizeof(target_path));
                if (err != PennFatErr_OK) {
                    LOG_ERR("[resolve_path] Failed to read symlink target for '%s' (Error %d)", component, err);
                    return err;
                }

                LOG_DEBUG("[resolve_path] Following symlink '%s' -> '%s'", component, target_path);

                // Recursively resolve the target path
                return resolve_path_internal(target_path, resolved, follow_symlinks, symlink_depth + 1);
            }

            // Not a symlink or not following symlinks, copy the resolved info
            *resolved = component_resolved;
            resolved->parent_dir_block = parent_dir;
            return PennFatErr_OK;
        }

        // Not the last component, check if it's a directory
        if (component_resolved.entry.type != 2) {
            // Not a directory, can't continue path traversal
            resolved->found = false;
            resolved->parent_dir_block = parent_dir;
            return PennFatErr_NOTDIR;
        }

        // Continue to the next component
        current_dir = component_resolved.entry.first_block;
        component = next_component;
    }

    // If we get here, the path ended with a trailing slash
    // Return the last directory we found
    resolved->found = true;
    resolved->is_root = (current_dir == 1);
    resolved->entry_block = current_dir;
    resolved->entry_index_in_block = -1; // Not applicable for directories
    resolved->parent_dir_block = parent_dir;

    // Set up directory entry
    memset(&resolved->entry, 0, sizeof(dir_entry_t));
    strcpy(resolved->entry.name, "."); // Use '.' as a placeholder
    resolved->entry.type = 2; // Directory
    resolved->entry.perm = DEF_PERM;
    resolved->entry.first_block = current_dir;
    resolved->entry.mtime = time(NULL);

    return PennFatErr_OK;
}

/*
 * resolve_path: Wrapper for resolve_path_internal that follows symlinks by default.
 */
static PennFatErr resolve_path(const char *path, resolved_path_t *resolved) {
    return resolve_path_internal(path, resolved, true, 0); // Follow symlinks, start at depth 0
}

/*
 * resolve_path_no_follow: Wrapper for resolve_path_internal that doesn't follow symlinks.
 */
static PennFatErr resolve_path_no_follow(const char *path, resolved_path_t *resolved) {
    return resolve_path_internal(path, resolved, false, 0); // Don't follow symlinks
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
PennFatErr k_open(const char *path, int mode) {
    if (!g_mounted) {
        LOG_WARN("[k_open] Failed to open file '%s': Filesystem not mounted.", path);
        return PennFatErr_NOT_MOUNTED; 
    }
    if (!path) { // Check for NULL path explicitly
        LOG_ERR("[k_open] Failed to open file: Invalid path (NULL).");
        return PennFatErr_INVAD;
    }
     // Allow empty path only if relative (handled by resolve_path correctly)
     if (path[0] == '\0' && g_cwd_block == 1) {
          LOG_ERR("[k_open] Failed to open file: Invalid path (empty absolute path).");
         return PennFatErr_INVAD;
     }

    if (!is_valid_mode(mode)) {
        LOG_ERR("[k_open] Failed to open file '%s': Invalid mode %d.", path, mode);
        return PennFatErr_INVAD;
    }

    LOG_INFO("[k_open] Opening path '%s' with mode %d", path, mode);

    resolved_path_t resolved;
    PennFatErr err = resolve_path(path, &resolved);
    if (err != PennFatErr_OK && err != PennFatErr_NOTDIR) { // NOTDIR is ok if opening last component
        LOG_ERR("[k_open] Path resolution failed for '%s' with error %d", path, err);
        return err;
    }


    int sys_idx = -1; // Index in the system-wide file table
    int dir_entry_block = -1; // Block where the directory entry resides
    int dir_entry_index = -1; // Index within that block

    if (resolved.found) {
         // Path exists. Check permissions and type.
         if (resolved.entry.type == 2) {
             LOG_ERR("[k_open] Cannot open '%s': It is a directory.", path);
             return PennFatErr_ISDIR;
         }
         // TODO: Add symlink handling: if resolved.entry.type == 4, resolve the link target recursively.

        // Check permissions based on mode
        if ((REQ_READ_PERM(mode) && !CAN_READ(resolved.entry.perm)) ||
            (REQ_WRITE_PERM(mode) && !CAN_WRITE(resolved.entry.perm))) {
            LOG_ERR("[k_open] Permission denied for file '%s'. Required mode %d, has perm %u", path, mode, resolved.entry.perm);
            return PennFatErr_PERM;
        }

        dir_entry_block = resolved.entry_block;
        dir_entry_index = resolved.entry_index_in_block;

        // If opening for write (not append), truncate the file
        if (HAS_WRITE(mode) && !HAS_APPEND(mode)) {
            LOG_DEBUG("[k_open] Truncating file '%s' (block %u, index %d)", path, dir_entry_block, dir_entry_index);
             // Free existing block chain
             err = free_block_chain(resolved.entry.first_block);
             if (err != PennFatErr_OK) {
                 LOG_ERR("[k_open] Failed to free blocks during truncation for '%s' (Error %d).", path, err);
                 return err;
             }
             // Allocate a single new block (or reuse first if possible?) - simpler to always alloc new
             int first_block = allocate_free_block();
             if (first_block < 0) {
                  LOG_ERR("[k_open] Failed to allocate first block during truncation for '%s'.", path);
                 return PennFatErr_NOSPACE;
             }

            // Update the directory entry
            resolved.entry.first_block = (uint16_t)first_block;
            resolved.entry.size = 0;
            resolved.entry.mtime = time(NULL);
            err = write_dirent(dir_entry_block, dir_entry_index, &resolved.entry);
            if (err != PennFatErr_OK) {
                 LOG_ERR("[k_open] Failed to write updated dirent during truncation for '%s' (Error %d).", path, err);
                 // Attempt rollback? Free the newly allocated block.
                 g_fat[first_block] = FAT_FREE;
                 return err;
            }
    }

        // Find or create system file table entry
        // Need the "canonical" index (block + index in block) to uniquely identify the file
        // We'll synthesize one for the SWFT lookup, although it's not ideal.
        // A better approach might store inode number if we had one, or use path resolution result.
        // For now, use block+index combo as key.
        int combined_index = (dir_entry_block << 16) | dir_entry_index; // Pseudo-inode
        sys_idx = find_and_increment_sysfile(combined_index); // Modify SWFT helpers
    if (sys_idx < 0) {
              sys_idx = create_sysfile_entry_from_resolved(&resolved, combined_index); // Modify SWFT helpers
             if (sys_idx < 0) {
                 LOG_ERR("[k_open] Failed to create system file entry for '%s'.", path);
                 return PennFatErr_OUTOFMEM;
             }
         }

    } else {
        // Path does not exist. Check if creation is allowed.
        if (!HAS_CREATE(mode)) {
            LOG_INFO("[k_open] Failed to open file '%s': File does not exist and create flag not set.", path);
            return PennFatErr_EXISTS; // No such file or directory
        }
        // Check parent directory exists and is writeable
        if (resolved.parent_dir_block == FAT_FREE || resolved.parent_dir_block == FAT_EOC) {
             LOG_ERR("[k_open] Cannot create file '%s': Parent directory does not exist.", path);
             return PennFatErr_EXISTS;
        }
        // (Skipping parent write perm check for now, like in mkdir)

        // Get the filename part
        char *last_slash = strrchr(path, '/');
        const char *filename = last_slash ? last_slash + 1 : path;
         if (strlen(filename) >= sizeof(resolved.entry.name)) {
             LOG_ERR("[k_open] Filename '%s' is too long.", filename);
             return PennFatErr_INVAD;
         }

        // Allocate first block for the new file
        int first_block = allocate_free_block();
        if (first_block < 0) {
             LOG_ERR("[k_open] Failed to allocate first block for new file '%s'.", filename);
            return PennFatErr_NOSPACE;
        }

        // Create the new directory entry
        dir_entry_t new_entry;
        memset(&new_entry, 0, sizeof(dir_entry_t));
        strncpy(new_entry.name, filename, sizeof(new_entry.name) - 1);
        new_entry.type = 1; // Regular file
        new_entry.perm = DEF_PERM; // Default permissions
        new_entry.first_block = (uint16_t)first_block;
        new_entry.size = 0;
        new_entry.mtime = time(NULL);

        // Add entry to parent directory
        err = add_dirent_to_dir(resolved.parent_dir_block, &new_entry);
        if (err != PennFatErr_OK) {
             LOG_ERR("[k_open] Failed to add entry for '%s' to parent directory block %u (Error %d)", filename, resolved.parent_dir_block, err);
             g_fat[first_block] = FAT_FREE; // Rollback block allocation
             return err;
        }
        LOG_DEBUG("[k_open] Created new file '%s' in directory block %u", filename, resolved.parent_dir_block);

        // We need the block/index where the *new* entry was placed to create the SWFT entry
        // add_dirent_to_dir should ideally return this info. Let's modify it or re-find it.
        // For now, re-resolve the path to get the created entry's details.
        resolved_path_t created_resolved;
        err = resolve_path(path, &created_resolved);
        // changes made by Ganlin
         if (err == PennFatErr_OK &&  created_resolved.found) { 
            

         } else {
            LOG_ERR("[k_open] Failed to re-resolve path '%s' after creation (Error %d). Inconsistency likely.", path, err);
            // Clean up? Maybe remove the entry we just added? Difficult.
            return err ? err : PennFatErr_IO;; // Indicate a problem
         }
         dir_entry_block = created_resolved.entry_block;
         dir_entry_index = created_resolved.entry_index_in_block;
         memcpy(&resolved.entry, &created_resolved.entry, sizeof(dir_entry_t)); // Update resolved info

        // Create system file table entry
        int combined_index = (dir_entry_block << 16) | dir_entry_index; // Pseudo-inode
        sys_idx = create_sysfile_entry_from_resolved(&created_resolved, combined_index); // Modify SWFT helpers
         if (sys_idx < 0) {
             LOG_ERR("[k_open] Failed to create system file entry for new file '%s'.", path);
             // Attempt rollback? Remove directory entry, free block chain.
             dir_entry_t deleted_entry;
             memset(&deleted_entry, 0, sizeof(dir_entry_t));
             deleted_entry.name[0] = 1; // Mark as deleted
             write_dirent(dir_entry_block, dir_entry_index, &deleted_entry);
             free_block_chain(new_entry.first_block);
             return PennFatErr_OUTOFMEM;
         }
    }

    // Assign a free file descriptor
    for (int fd = 0; fd < MAX_FD; fd++) {
        if (!g_fd_table[fd].in_use) {
            g_fd_table[fd].in_use = true;
            g_fd_table[fd].sysfile_index = sys_idx;
            g_fd_table[fd].mode = mode;
            // Set offset: end for append, 0 otherwise
             g_fd_table[fd].offset = (HAS_APPEND(mode)) ? resolved.entry.size : 0;


            LOG_INFO("[k_open] Assigned file descriptor %d for path '%s' (SWFT index %d)", fd, path, sys_idx);
            LOG_DEBUG("[k_open] FD %d: mode=%d, offset=%u", fd, mode, g_fd_table[fd].offset);
            return fd; // Return the allocated file descriptor index
        }
    }

    // No free file descriptors
    LOG_ERR("[k_open] Failed to open file '%s': No free file descriptors available.", path);
    // Release the SWFT entry reference we acquired/created
    release_sysfile_entry(sys_idx); // Modify SWFT helpers
    return PennFatErr_OUTOFMEM; // Or a specific "too many open files" error
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

    if (HAS_WRITE(fdesc->mode)) {
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

    if (HAS_READ(fdesc->mode)) {
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

    int sys_idx = g_fd_table[fd].sysfile_index;
    g_fd_table[fd].in_use = false;
    release_sysfile_entry(sys_idx);

    LOG_INFO("[k_close] Successfully closed file descriptor %d (sysfile index %d).", fd, sys_idx);

    return PennFatErr_SUCCESS;
}

/** 
 * Remove the file. Be careful how you implement this, like Linux, you should 
 * not be able to delete a file that is in use by another process. Furthermore,
 * consider where updates will be necessary. You do not necessarily need to clear
 * the previous data in the data region, but should at least note this area as
 * 'nullified' or fresh and ready to write to, elsewhere.
 */
PennFatErr k_unlink(const char *path) {
    if (!g_mounted) {
        LOG_WARN("[k_unlink] Failed to unlink '%s': Filesystem not mounted.", path);
        return PennFatErr_NOT_MOUNTED; 
    }
    if (!path || path[0] == '\0' || strcmp(path, "/") == 0 || strcmp(path, ".") == 0 || strcmp(path, "..") == 0) {
         LOG_ERR("[k_unlink] Invalid path '%s' for unlink.", path);
        return PennFatErr_INVAD;
    }
    LOG_INFO("[k_unlink] Attempting to unlink: '%s'", path);

    resolved_path_t resolved;
    PennFatErr err = resolve_path(path, &resolved);
     if (err != PennFatErr_OK) {
        LOG_ERR("[k_unlink] Path resolution failed for '%s' with error %d", path, err);
        return err;
    }

    if (!resolved.found || resolved.is_root) { // Cannot unlink root
        LOG_ERR("[k_unlink] Failed to unlink '%s': Path does not exist or is root.", path);
        return PennFatErr_EXISTS;
    }

    // Check if it's a directory - use rmdir instead
    if (resolved.entry.type == 2) {
        LOG_ERR("[k_unlink] Failed to unlink '%s': Is a directory. Use rmdir.", path);
        return PennFatErr_ISDIR;
    }
     // TODO: Add symlink handling? Unlink should remove the link itself.

    // Check parent directory permissions (need write permission in parent)
     // (Skipping parent write perm check for now)
      if (resolved.parent_dir_block != 1) {
          LOG_WARN("[k_unlink] Skipping parent permission check for non-root parent (block %u).", resolved.parent_dir_block);
     }

    // Check if the file is currently open (check SWFT reference count)
    int pseudo_inode = (resolved.entry_block << 16) | resolved.entry_index_in_block;
    int sys_idx = find_and_increment_sysfile(pseudo_inode);
    if (sys_idx >= 0) { // Found an entry
        if (g_sysfile_table[sys_idx].ref_count > 1) { // It's open by at least one FD (ref > 1 after increment)
             g_sysfile_table[sys_idx].ref_count--; // Decrement back
             LOG_ERR("[k_unlink] Failed to unlink '%s': File is currently open.", path);
             return PennFatErr_BUSY;
        }
        // File exists in SWFT but ref count is 1 (only our check incremented it), safe to remove
        g_sysfile_table[sys_idx].ref_count--; // Decrement back
        // We should probably mark the SWFT entry invalid now, or let release handle it?
        // Let release handle it, but the check prevents deleting open files.
    }


    // Free the blocks used by the file (if any)
    if (resolved.entry.first_block != FAT_EOC && resolved.entry.first_block != FAT_FREE) {
        err = free_block_chain(resolved.entry.first_block);
        if (err != PennFatErr_OK) {
            LOG_ERR("[k_unlink] Failed to free blocks for '%s' starting at %u (Error %d).",
                     path, resolved.entry.first_block, err);
            // Continue to remove dirent, but log error. FS state might be inconsistent.
        } else {
             LOG_DEBUG("[k_unlink] Freed block chain starting at %u for file '%s'", resolved.entry.first_block, path);
    }
    }


    // Mark the directory entry as deleted in the parent directory
    dir_entry_t deleted_entry;
    memset(&deleted_entry, 0, sizeof(dir_entry_t));
    deleted_entry.name[0] = 1; // Mark as deleted
    err = write_dirent(resolved.entry_block, resolved.entry_index_in_block, &deleted_entry);
     if (err != PennFatErr_OK) {
         LOG_ERR("[k_unlink] Failed to write deleted marker for '%s' in parent block %u (Error %d)", resolved.entry.name, resolved.entry_block, err);
         return err; // Failed to update parent directory
     }
     LOG_DEBUG("[k_unlink] Marked entry for '%s' as deleted in parent block %u index %d", resolved.entry.name, resolved.entry_block, resolved.entry_index_in_block);

    LOG_INFO("[k_unlink] Unlinked path '%s'.", path);
    return PennFatErr_OK;
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
PennFatErr k_ls(const char *path) {
    if (!g_mounted) {
        LOG_WARN("[k_ls] Failed to list files: Filesystem not mounted.");
        return PennFatErr_NOT_MOUNTED; 
    }

    const char *target_path = (path && path[0] != '\0') ? path : "."; // Default to CWD if path is NULL or empty
    LOG_INFO("[k_ls] Listing directory contents for path: '%s'", target_path);


    // 1. Resolve the path to find the target directory
    resolved_path_t resolved;
    PennFatErr err = resolve_path(target_path, &resolved);
    if (err != PennFatErr_OK) {
        LOG_ERR("[k_ls] Path resolution failed for '%s' with error %d", target_path, err);
        return err;
    }

    if (!resolved.found) {
        LOG_ERR("[k_ls] Cannot list directory '%s': Path does not exist.", target_path);
        return PennFatErr_EXISTS; // No such file or directory
    }

    uint16_t dir_to_list_block;
    if (resolved.is_root) {
        dir_to_list_block = 1; // Root directory
    } else if (resolved.entry.type == 2) {
        dir_to_list_block = resolved.entry.first_block; // It's a directory
    } else {
        LOG_ERR("[k_ls] Cannot list '%s': Not a directory.", target_path);
        return PennFatErr_NOTDIR;
    }


    // 2. Iterate through the directory block chain and print entries
    printf("Listing directory block %u:\n", dir_to_list_block);
    printf("      Block Perm Size       Timestamp             Name\n"); // Header format like original
    printf("------------------------------------------------------------\n");

    uint16_t current_block = dir_to_list_block;
    char *block_buffer = malloc(g_block_size);
    if (!block_buffer) return PennFatErr_OUTOFMEM;

    dir_entry_t *dir_entries = (dir_entry_t *)block_buffer;
    uint32_t entries_per_block = g_block_size / sizeof(dir_entry_t);
    char perm_str[4];
    char time_str[20];
    struct tm *tm_info;
    int entries_found = 0;

    while (current_block != FAT_EOC && current_block != FAT_FREE) {
        if (read_block(block_buffer, current_block) != 0) {
            fprintf(stderr, "Error reading block %u for ls\n", current_block); // Use stderr for direct errors
            free(block_buffer);
            return PennFatErr_IO;
        }

        for (uint32_t i = 0; i < entries_per_block; i++) {
            // Skip empty or deleted entries
             if (dir_entries[i].name[0] == 0 || (uint8_t)dir_entries[i].name[0] == 1 || (uint8_t)dir_entries[i].name[0] == 2) {
                 if (dir_entries[i].name[0] == 0) break; // End of directory marker
                 continue;
             }

            entries_found++;
            tm_info = localtime(&dir_entries[i].mtime);
            // Handle potential NULL from localtime if time_t is invalid (unlikely)
            if (tm_info) {
                strftime(time_str, sizeof(time_str), "%b %d %H:%M", tm_info);
            } else {
                 strncpy(time_str, "??? ?? ??:??", sizeof(time_str));
            }
            perm_to_str(dir_entries[i].perm, perm_str);

            // Print type prefix (d for directory, l for link, - for file)
            char type_char = '-';
            if(dir_entries[i].type == 2) type_char = 'd';
            else if (dir_entries[i].type == 4) type_char = 'l';

            printf("%10u %c%s %-10u %s %s", // Adjusted format
                   dir_entries[i].first_block,
                   type_char,
                   perm_str,
                   dir_entries[i].size,
                   time_str,
                   dir_entries[i].name);

            // If it's a symlink, print the target
             if (dir_entries[i].type == 4) {
                 // The target path is stored directly in the "data blocks" for the link entry
                 // We need to read the first block to get the target string
                 char link_target_buffer[g_block_size]; // Assume target fits in one block for now
                 if (dir_entries[i].first_block != FAT_EOC && dir_entries[i].first_block != FAT_FREE) {
                     if (read_block(link_target_buffer, dir_entries[i].first_block) == 0) {
                          // Ensure null termination within the buffer size
                          link_target_buffer[g_block_size - 1] = '\0';
                         printf(" -> %s", link_target_buffer);
                     } else {
                         printf(" -> [Error reading target]");
                     }
                 } else {
                      printf(" -> [Invalid target block]");
                 }

             }
             printf("\n");

        } // End for loop through entries in block

        if (dir_entries[0].name[0] == 0) break; // Break outer loop if end marker found

        // Move to the next block in the directory chain
        current_block = g_fat[current_block];
        }

    free(block_buffer);

    if (entries_found == 0) {
        printf("(Directory is empty)\n");
    }
     printf("------------------------------------------------------------\n");

    return PennFatErr_OK;
}

/*
 * k_touch: A kernel-level "touch" operation.
 *
 * Behavior:
 *   - If a file with fname exists, update its mtime to the current time.
 *   - Otherwise, create a new file entry with 0 size and the current mtime.
 *
 * Returns:
 *   0 on success, or a negative error code.
 *
 * This function leverages lookup_entry() with create=true.
 */
 PennFatErr k_touch(const char *path) {
    if (!g_mounted) {
        LOG_WARN("[k_touch] Failed to touch '%s': Filesystem not mounted.", path);
        return PennFatErr_NOT_MOUNTED;
    }
     if (!path || path[0] == '\0') {
        LOG_ERR("[k_touch] Failed to touch: Invalid path.");
        return PennFatErr_INVAD;
    }
    LOG_INFO("[k_touch] Touching path: '%s'", path);

    resolved_path_t resolved;
    PennFatErr err = resolve_path(path, &resolved);
     if (err != PennFatErr_OK && err != PennFatErr_NOTDIR) { // Allow NOTDIR if touching final component
        LOG_ERR("[k_touch] Path resolution failed for '%s' with error %d", path, err);
        return err;
    }

    if (resolved.found) {
        // Path exists. Update timestamp.
         if (resolved.is_root) {
             LOG_WARN("[k_touch] Cannot touch root directory '/'.");
             return PennFatErr_ISDIR; // Or INVAD
         }
         if (resolved.entry.type == 2) {
              LOG_INFO("[k_touch] Path '%s' is a directory. Updating timestamp.", path);
             // Allow touching directories? Standard touch does.
         } else if (resolved.entry.type == 4) {
             LOG_INFO("[k_touch] Path '%s' is a symlink. Updating timestamp of the link itself.", path);
             // Update link timestamp, not target
         }

        resolved.entry.mtime = time(NULL);
        err = write_dirent(resolved.entry_block, resolved.entry_index_in_block, &resolved.entry);
        if (err != PennFatErr_OK) {
            LOG_ERR("[k_touch] Failed to write updated timestamp for '%s' (Error %d)", path, err);
            return err;
        }
        LOG_DEBUG("[k_touch] Updated timestamp for existing path '%s'", path);
        return PennFatErr_OK;

    } else {
        // Path does not exist. Create it as a regular file.
        // Check parent directory exists and is writeable
        if (resolved.parent_dir_block == FAT_FREE || resolved.parent_dir_block == FAT_EOC) {
             LOG_ERR("[k_touch] Cannot create file '%s': Parent directory does not exist.", path);
        return PennFatErr_EXISTS;
    }
        // (Skipping parent write perm check for now)

        // Get the filename part
        char *last_slash = strrchr(path, '/');
        const char *filename = last_slash ? last_slash + 1 : path;
         if (strlen(filename) >= sizeof(resolved.entry.name)) {
             LOG_ERR("[k_touch] Filename '%s' is too long.", filename);
             return PennFatErr_INVAD;
         }
          if (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0) {
              LOG_ERR("[k_touch] Cannot create file named '.' or '..'.");
        return PennFatErr_INVAD;
    }

        // Allocate first block for the new file (even though size is 0)
        int first_block = allocate_free_block();
        if (first_block < 0) {
             LOG_ERR("[k_touch] Failed to allocate first block for new file '%s'.", filename);
            return PennFatErr_NOSPACE;
        }

        // Create the new directory entry
        dir_entry_t new_entry;
        memset(&new_entry, 0, sizeof(dir_entry_t));
        strncpy(new_entry.name, filename, sizeof(new_entry.name) - 1);
        new_entry.type = 1; // Regular file
        new_entry.perm = DEF_PERM; // Default permissions
        new_entry.first_block = (uint16_t)first_block; // Point to allocated block
        new_entry.size = 0; // Size is 0
        new_entry.mtime = time(NULL);

        // Add entry to parent directory
        err = add_dirent_to_dir(resolved.parent_dir_block, &new_entry);
        if (err != PennFatErr_OK) {
             LOG_ERR("[k_touch] Failed to add entry for '%s' to parent directory block %u (Error %d)", filename, resolved.parent_dir_block, err);
             g_fat[first_block] = FAT_FREE; // Rollback block allocation
             return err;
        }
        LOG_DEBUG("[k_touch] Created new file '%s' in directory block %u", filename, resolved.parent_dir_block);
        return PennFatErr_OK;
    }
}

// Old k_rename function has been replaced by a new hierarchical version below

/*
 * k_chmod: Changes the permission of the file with name fname to new_perm.
 * Allowed new_perm values: 0, 2, 4, 5, 6, or 7.
 * Returns PennFatErr_SUCCESS on success or a negative error code.
 */
PennFatErr k_chmod(const char *path, uint8_t new_perm) {
    if (!g_mounted) {
        LOG_WARN("[k_chmod] Failed to chmod '%s': Filesystem not mounted.", path);
        return PennFatErr_NOT_MOUNTED;
    }
    if (!path || path[0] == '\0') {
        LOG_ERR("[k_chmod] Failed to chmod: Invalid path.");
        return PennFatErr_INVAD;
    }
    if (!VALID_PERM(new_perm)) {
        LOG_ERR("[k_chmod] Failed to chmod '%s': Invalid permission value %u.", path, new_perm);
        return PennFatErr_INVAD;
    }
    LOG_INFO("[k_chmod] Changing mode for path '%s' to %u", path, new_perm);

    resolved_path_t resolved;
    PennFatErr err = resolve_path(path, &resolved);
     if (err != PennFatErr_OK) {
        LOG_ERR("[k_chmod] Path resolution failed for '%s' with error %d", path, err);
        return err;
    }

    if (!resolved.found || resolved.is_root) { // Cannot chmod root
        LOG_ERR("[k_chmod] Failed to chmod '%s': Path does not exist or is root.", path);
        return PennFatErr_EXISTS;
    }
     // TODO: Add symlink handling? Should chmod affect the link or the target? Standard chmod affects target.

    // Update the permission and timestamp in the directory entry
    resolved.entry.perm = new_perm;
    resolved.entry.mtime = time(NULL);
    err = write_dirent(resolved.entry_block, resolved.entry_index_in_block, &resolved.entry);
    if (err != PennFatErr_OK) {
        LOG_ERR("[k_chmod] Failed to write updated permissions for '%s' (Error %d)", path, err);
        return err;
    }

    // Optional: Update SWFT entry if open? Permissions are usually not cached there.
    // int pseudo_inode = (resolved.entry_block << 16) | resolved.entry_index_in_block;
    // int sys_idx = find_and_increment_sysfile(pseudo_inode);
    // if (sys_idx >= 0) {
    //     // g_sysfile_table[sys_idx].perm = new_perm; // If we stored perm there
    //     g_sysfile_table[sys_idx].mtime = resolved.entry.mtime;
    //     g_sysfile_table[sys_idx].ref_count--; // Decrement back
    // }


    LOG_INFO("[k_chmod] Changed permissions for '%s' to %u.", path, new_perm);
    return PennFatErr_OK;
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

    /* Set up the superblock info from FAT[0]:
       - g_superblock.fat_block_count is set from fat_blocks.
       - Data blocks start at index 2: index 0 holds formatting info and index 1 is reserved for the root directory.
    */
    g_superblock.fat_block_count = fat_blocks;
    g_superblock.data_start_block = 2;


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

    /* No block cache initialization needed */

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

    /* Close all open file descriptors to ensure metadata is written back */
    for (int fd = 0; fd < MAX_FD; fd++) {
        if (g_fd_table[fd].in_use) {
            LOG_INFO("[k_unmount] Auto-closing open file descriptor %d", fd);
            k_close(fd);
        }
    }

    /* No block cache to flush */

    /* Write the root directory directly to disk */
    LOG_INFO("[k_unmount] Writing root directory to disk...");
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

    /* Ensure all written data is flushed to the disk */
    LOG_INFO("[k_unmount] Syncing all filesystem data to disk...");
    if (fsync(g_fs_fd) < 0) {
        LOG_CRIT("[k_unmount] Failed to sync filesystem data to disk: %s", strerror(errno));
        // Even if fsync fails, try to close the file descriptor
        close(g_fs_fd);
        g_fs_fd = -1; // Mark as closed
        return PennFatErr_INTERNAL;
    }
    LOG_INFO("[k_unmount] All filesystem data successfully synced to disk.");

    /* Close the filesystem file */
    if (close(g_fs_fd) < 0) {
        LOG_ERR("[k_unmount] Failed to close filesystem file: %s", strerror(errno));
        return PennFatErr_INTERNAL;
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
 * the root directory file's first block) is allocated.
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
        return PennFatErr_INTERNAL;
    }
    
    /* Allocate and initialize the FAT array */
    uint16_t *fat_array = malloc(fat_region_size);
    if (!fat_array) {
        perror("mkfs: malloc (fat_array)");
        close(fd);
        return PennFatErr_OUTOFMEM;
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
        return PennFatErr_INTERNAL;
    }
    if (write(fd, fat_array, fat_region_size) != fat_region_size) {
        perror("mkfs: write (FAT region)");
        free(fat_array);
        close(fd);
        return PennFatErr_INTERNAL;
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
        fs_name, blocks_in_fat, block_size, block_size_config);

    close(fd);
    return PennFatErr_SUCCESS;
}

PennFatErr k_chdir(const char *path) {
    if (!g_mounted) return PennFatErr_NOT_MOUNTED;
    if (!path) return PennFatErr_INVAD; // Allow empty path? Let resolve_path handle it for now.

    LOG_INFO("[k_chdir] Attempting to change directory to: '%s'", path);

    resolved_path_t resolved;
    PennFatErr err = resolve_path(path, &resolved);
    if (err != PennFatErr_OK) {
        LOG_ERR("[k_chdir] Path resolution failed for '%s' with error %d", path, err);
        return err;
    }

    if (!resolved.found) {
        LOG_ERR("[k_chdir] Cannot change directory to '%s': Path does not exist.", path);
        return PennFatErr_EXISTS; // No such file or directory
    }

    // Check if the resolved path is actually a directory
    // Special case: resolved.is_root is true if path was "/"
    if (resolved.is_root) {
         g_cwd_block = 1; // Change to root
         LOG_INFO("[k_chdir] Changed directory to root ('/')");
         return PennFatErr_OK;
    } else if (resolved.entry.type != 2) {
        LOG_ERR("[k_chdir] Cannot change directory to '%s': Not a directory.", path);
        return PennFatErr_NOTDIR;
    }

    // Path resolved to a directory entry, update CWD block
    g_cwd_block = resolved.entry.first_block;
    LOG_INFO("[k_chdir] Changed directory to '%s' (block %u)", path, g_cwd_block);
    return PennFatErr_OK;
}

// Helper to find the name of a directory given its block number by looking in its parent
static PennFatErr find_dir_name_in_parent(uint16_t target_dir_block, uint16_t parent_dir_block, char *name_buf, size_t buf_size) {
    if (!g_mounted || !name_buf || buf_size == 0) return PennFatErr_INVAD;
    if (parent_dir_block == FAT_FREE || parent_dir_block == FAT_EOC || target_dir_block == FAT_FREE || target_dir_block == FAT_EOC) {
         return PennFatErr_INVAD;
    }
    if (target_dir_block == 1) { // Root directory special case
        if (buf_size > 0) name_buf[0] = '\0'; // Root has no name in its parent
        return PennFatErr_OK;
    }

    uint16_t current_block = parent_dir_block;
    char *block_buffer = malloc(g_block_size);
    if (!block_buffer) return PennFatErr_OUTOFMEM;

    dir_entry_t *dir_entries = (dir_entry_t *)block_buffer;
    uint32_t entries_per_block = g_block_size / sizeof(dir_entry_t);

    while (current_block != FAT_EOC && current_block != FAT_FREE) {
        if (read_block(block_buffer, current_block) != 0) {
            free(block_buffer);
            return PennFatErr_IO;
        }

        for (uint32_t i = 0; i < entries_per_block; i++) {
            // Check for active directory entries matching the target block
             if (dir_entries[i].name[0] != 0 && (uint8_t)dir_entries[i].name[0] != 1 && (uint8_t)dir_entries[i].name[0] != 2 &&
                 dir_entries[i].type == 2 && // Must be a directory
                 dir_entries[i].first_block == target_dir_block &&
                 strcmp(dir_entries[i].name, ".") != 0 && strcmp(dir_entries[i].name, "..") != 0) // Exclude '.' and '..'
             {
                   strncpy(name_buf, dir_entries[i].name, buf_size - 1);
                   name_buf[buf_size - 1] = '\0'; // Ensure null termination
                   LOG_DEBUG("[find_dir_name_in_parent] Found name '%s' for block %u in parent block %u", name_buf, target_dir_block, current_block);
                   free(block_buffer);
                   return PennFatErr_OK;
             }
             if (dir_entries[i].name[0] == 0) break; // End of directory marker
        }
        current_block = g_fat[current_block];
    }

    free(block_buffer);
    LOG_WARN("[find_dir_name_in_parent] Could not find name for block %u in parent %u", target_dir_block, parent_dir_block);
    return PennFatErr_EXISTS; // Name not found in parent
}

PennFatErr k_getcwd(char *buf, size_t size) {
    if (!g_mounted) return PennFatErr_NOT_MOUNTED;
    if (!buf || size == 0) return PennFatErr_INVAD;

    LOG_DEBUG("[k_getcwd] Getting current working directory (starting from block %u)", g_cwd_block);

    if (g_cwd_block == 1) { // Special case for root
        if (size < 2) return PennFatErr_RANGE; // Need space for "/" and null terminator
        strncpy(buf, "/", size);
         // Ensure null termination even if size is 1 (only space for '/')
         if (size > 0) buf[size - 1] = '\0';
        LOG_INFO("[k_getcwd] Current directory is root ('/')");
        return PennFatErr_OK;
    }

    char current_path[PATH_MAX] = ""; // Build path reversed
    char component[sizeof(((dir_entry_t*)0)->name) + 1]; // Max name length + slash
    uint16_t current_dir = g_cwd_block;
    uint16_t parent_dir = 0; // Will be found via ".." entry
    int safety_count = 0; // Prevent infinite loops
    const int max_depth = 64; // Arbitrary limit

    while (current_dir != 1 && safety_count < max_depth) {
         safety_count++;

        // Find the ".." entry in the current directory to get the parent block
        resolved_path_t dotdot_result;
        memset(&dotdot_result, 0, sizeof(resolved_path_t));
        PennFatErr err = find_entry_in_dir(current_dir, "..", &dotdot_result);
        if (err != PennFatErr_OK || !dotdot_result.found) {
            LOG_ERR("[k_getcwd] Failed to find '..' entry in directory block %u (Error %d)", current_dir, err);
            buf[0] = '?'; if (size > 1) buf[1] = '\0'; // Indicate error
            return PennFatErr_IO; // Or a more specific error
        }
        parent_dir = dotdot_result.entry.first_block; // Found parent block from '..'

        // Find the name of the current directory within its parent
        err = find_dir_name_in_parent(current_dir, parent_dir, component, sizeof(component) -1); // Leave space for slash
        if (err != PennFatErr_OK) {
             LOG_ERR("[k_getcwd] Failed to find name for block %u in parent block %u (Error %d)", current_dir, parent_dir, err);
             buf[0] = '?'; if (size > 1) buf[1] = '\0'; // Indicate error
             return PennFatErr_IO; // Or a more specific error
        }

        // Prepend "/component" to the current path
        char temp_path[PATH_MAX];
        snprintf(temp_path, PATH_MAX, "/%s%s", component, current_path); // Prepend
        strncpy(current_path, temp_path, PATH_MAX - 1);
        current_path[PATH_MAX - 1] = '\0';

        LOG_DEBUG("[k_getcwd] Current path component: '%s', Path built so far: '%s'", component, current_path);

        // Move up to the parent directory for the next iteration
        current_dir = parent_dir;
    }

     if (safety_count >= max_depth) {
          LOG_ERR("[k_getcwd] Exceeded maximum directory depth (%d). Path reconstruction failed.", max_depth);
          buf[0] = '?'; if (size > 1) buf[1] = '\0'; // Indicate error
          return PennFatErr_RANGE; // Or another error
     }

    // Handle the case where the path is empty (should only happen for root, handled above)
    // or if it just needs a leading slash if current_path remained empty.
    if (strlen(current_path) == 0) {
         if(size < 2) return PennFatErr_RANGE;
         strncpy(buf, "/", size);
         if (size > 0) buf[size - 1] = '\0';
    } else {
         // Final check: ensure the path fits in the buffer
         if (strlen(current_path) >= size) { // Check >= because we need space for null terminator
             LOG_ERR("[k_getcwd] Reconstructed path '%s' is too long for buffer size %zu", current_path, size);
             strncpy(buf, current_path, size -1);
             buf[size - 1] = '\0';
             return PennFatErr_RANGE; // Path too long for buffer
         }
         // Copy the final path to the output buffer
         strncpy(buf, current_path, size);
         // strncpy might not null-terminate if src is longer than size-1
         buf[size - 1] = '\0';
    }


    LOG_INFO("[k_getcwd] Current working directory: '%s'", buf);
    return PennFatErr_OK;
}

PennFatErr k_symlink(const char *target, const char *linkpath) {
    if (!g_mounted) {
        LOG_WARN("[k_symlink] Failed to create symlink '%s' -> '%s': Filesystem not mounted.", linkpath, target);
        return PennFatErr_NOT_MOUNTED;
    }
    if (!target || !linkpath || target[0] == '\0' || linkpath[0] == '\0') {
        LOG_ERR("[k_symlink] Failed to create symlink: Invalid paths.");
        return PennFatErr_INVAD;
    }
     LOG_INFO("[k_symlink] Creating symlink '%s' pointing to '%s'", linkpath, target);

    // 1. Resolve linkpath to find parent and check existence
    resolved_path_t link_resolved;
    PennFatErr err = resolve_path_no_follow(linkpath, &link_resolved);
     if (err != PennFatErr_OK && err != PennFatErr_NOTDIR) {
        LOG_ERR("[k_symlink] Path resolution failed for link path '%s' (Error %d)", linkpath, err);
        return err;
    }
     if (link_resolved.found) {
         LOG_ERR("[k_symlink] Cannot create link '%s': Path already exists.", linkpath);
         return PennFatErr_EXISTS;
     }
     if (link_resolved.parent_dir_block == FAT_FREE || link_resolved.parent_dir_block == FAT_EOC) {
         LOG_ERR("[k_symlink] Cannot create link '%s': Parent directory does not exist.", linkpath);
         return PennFatErr_EXISTS;
     }
     // (Skipping parent perm check)

    const char *link_filename = get_filename_from_path(linkpath);
     if (!link_filename || strlen(link_filename) == 0 || strlen(link_filename) >= sizeof(link_resolved.entry.name)) {
         LOG_ERR("[k_symlink] Invalid link filename derived from '%s'.", linkpath);
         return PennFatErr_INVAD;
     }
      if (strcmp(link_filename, ".") == 0 || strcmp(link_filename, "..") == 0) {
          LOG_ERR("[k_symlink] Cannot create link named '.' or '..'.");
          return PennFatErr_INVAD;
      }


    // 2. Allocate block(s) for target string
    //    Simplification: Assume target fits in one block for now.
    size_t target_len = strlen(target);
     if (target_len >= g_block_size) { // Check >= because we need null terminator
         LOG_ERR("[k_symlink] Target path '%s' is too long (max %u bytes).", target, g_block_size - 1);
         return PennFatErr_RANGE; // Or a different error? E2BIG?
     }

    int target_block = allocate_free_block();
     if (target_block < 0) {
         LOG_ERR("[k_symlink] Failed to allocate block for target string of '%s'.", linkpath);
         return PennFatErr_NOSPACE;
     }
     LOG_DEBUG("[k_symlink] Allocated block %d for target string.", target_block);

    // 3. Write target string to the block
    char *block_buffer = calloc(1, g_block_size); // Use calloc to zero-initialize
    if (!block_buffer) {
         g_fat[target_block] = FAT_FREE; // Rollback alloc
         return PennFatErr_OUTOFMEM;
     }
    strncpy(block_buffer, target, g_block_size - 1); // Copy target, ensuring space for null term
    block_buffer[g_block_size - 1] = '\0'; // Ensure null termination

    err = write_block(block_buffer, target_block);
    free(block_buffer);
    if (err != 0) {
        LOG_ERR("[k_symlink] Failed to write target string to block %d for link '%s'", target_block, linkpath);
        g_fat[target_block] = FAT_FREE; // Rollback alloc
        return PennFatErr_IO;
    }

    // Ensure the symlink target data is immediately written to disk
    fdatasync(g_fs_fd);
    LOG_DEBUG("[k_symlink] Target data flushed to disk for symlink '%s' -> '%s'", linkpath, target);

    // 4. Create directory entry for the link
    dir_entry_t link_entry;
    memset(&link_entry, 0, sizeof(dir_entry_t));
    strncpy(link_entry.name, link_filename, sizeof(link_entry.name) - 1);
    link_entry.type = 4; // Symbolic link
    link_entry.perm = DEF_PERM | PERM_EXEC; // Default link perms (rwxrwxrwx often)
    link_entry.first_block = (uint16_t)target_block;
    link_entry.size = target_len; // Store length of target string
    link_entry.mtime = time(NULL);

    // 5. Add link entry to parent directory
    err = add_dirent_to_dir(link_resolved.parent_dir_block, &link_entry);
    if (err != PennFatErr_OK) {
        LOG_ERR("[k_symlink] Failed to add entry for link '%s' to parent block %u (Error %d)", link_filename, link_resolved.parent_dir_block, err);
        free_block_chain(target_block); // Rollback target block allocation
        return err;
    }

    LOG_INFO("[k_symlink] Successfully created link '%s' -> '%s'", linkpath, target);
    return PennFatErr_OK;
}



/**
 * k_mkdir: Creates a new directory at the specified path.
 */
PennFatErr k_mkdir(const char *path) {
    if (!g_mounted) {
        LOG_WARN("[k_mkdir] Failed to create directory '%s': Filesystem not mounted.", path);
        return PennFatErr_NOT_MOUNTED;
    }
    if (!path || path[0] == '\0') {
        LOG_ERR("[k_mkdir] Failed to create directory: Invalid path.");
        return PennFatErr_INVAD;
    }

    LOG_INFO("[k_mkdir] Creating directory at path: '%s'", path);

    // 1. Resolve the path to check if it already exists
    resolved_path_t resolved;
    PennFatErr err = resolve_path(path, &resolved);
    if (err != PennFatErr_OK && err != PennFatErr_NOTDIR) {
        LOG_ERR("[k_mkdir] Path resolution failed for '%s' with error %d", path, err);
        return err;
    }

    if (resolved.found) {
        LOG_ERR("[k_mkdir] Cannot create directory '%s': Path already exists.", path);
        return PennFatErr_EXISTS;
    }

    // 2. Check if parent directory exists and is writable
    if (resolved.parent_dir_block == FAT_FREE || resolved.parent_dir_block == FAT_EOC) {
        LOG_ERR("[k_mkdir] Cannot create directory '%s': Parent directory does not exist.", path);
        return PennFatErr_EXISTS;
    }

    // 3. Get the directory name from the path
    const char *dirname = get_filename_from_path(path);
    if (!dirname || strlen(dirname) == 0 || strlen(dirname) >= sizeof(resolved.entry.name)) {
        LOG_ERR("[k_mkdir] Invalid directory name derived from '%s'.", path);
        return PennFatErr_INVAD;
    }
    if (strcmp(dirname, ".") == 0 || strcmp(dirname, "..") == 0) {
        LOG_ERR("[k_mkdir] Cannot create directory named '.' or '..'.");
        return PennFatErr_INVAD;
    }

    // 4. Allocate a block for the new directory
    int dir_block = allocate_free_block();
    if (dir_block < 0) {
        LOG_ERR("[k_mkdir] Failed to allocate block for new directory '%s'.", dirname);
        return PennFatErr_NOSPACE;
    }

    // 5. Create the directory entry in the parent directory
    dir_entry_t new_entry;
    memset(&new_entry, 0, sizeof(dir_entry_t));
    strncpy(new_entry.name, dirname, sizeof(new_entry.name) - 1);
    new_entry.type = 2; // Directory
    new_entry.perm = DEF_PERM; // Default permissions
    new_entry.first_block = (uint16_t)dir_block;
    new_entry.size = 0; // Size is 0 for directories
    new_entry.mtime = time(NULL);

    err = add_dirent_to_dir(resolved.parent_dir_block, &new_entry);
    if (err != PennFatErr_OK) {
        LOG_ERR("[k_mkdir] Failed to add entry for '%s' to parent directory block %u (Error %d)", dirname, resolved.parent_dir_block, err);
        g_fat[dir_block] = FAT_FREE; // Rollback block allocation
        return err;
    }

    // 6. Initialize the directory with '.' and '..' entries
    char *block_buffer = calloc(1, g_block_size); // Use calloc to zero-initialize
    if (!block_buffer) {
        LOG_ERR("[k_mkdir] Failed to allocate memory for directory initialization.");
        g_fat[dir_block] = FAT_FREE; // Rollback block allocation
        return PennFatErr_OUTOFMEM;
    }

    dir_entry_t *dir_entries = (dir_entry_t *)block_buffer;

    // Create '.' entry (points to self)
    strcpy(dir_entries[0].name, ".");
    dir_entries[0].type = 2; // Directory
    dir_entries[0].perm = DEF_PERM;
    dir_entries[0].first_block = (uint16_t)dir_block;
    dir_entries[0].mtime = time(NULL);

    // Create '..' entry (points to parent)
    strcpy(dir_entries[1].name, "..");
    dir_entries[1].type = 2; // Directory
    dir_entries[1].perm = DEF_PERM;
    dir_entries[1].first_block = resolved.parent_dir_block;
    dir_entries[1].mtime = time(NULL);

    // Write the initialized directory block
    if (write_block(block_buffer, dir_block) != 0) {
        LOG_ERR("[k_mkdir] Failed to write initialized directory block %u.", dir_block);
        free(block_buffer);
        g_fat[dir_block] = FAT_FREE; // Rollback block allocation
        return PennFatErr_IO;
    }

    free(block_buffer);
    LOG_INFO("[k_mkdir] Successfully created directory '%s' at block %u.", path, dir_block);
    return PennFatErr_OK;
}

/**
 * k_rmdir: Removes a directory at the specified path.
 */
PennFatErr k_rmdir(const char *path) {
    if (!g_mounted) {
        LOG_WARN("[k_rmdir] Failed to remove directory '%s': Filesystem not mounted.", path);
        return PennFatErr_NOT_MOUNTED;
    }
    if (!path || path[0] == '\0' || strcmp(path, "/") == 0) {
        LOG_ERR("[k_rmdir] Cannot remove directory '%s': Invalid path or root directory.", path);
        return PennFatErr_INVAD;
    }

    LOG_INFO("[k_rmdir] Removing directory at path: '%s'", path);

    // 1. Resolve the path to find the directory
    resolved_path_t resolved;
    PennFatErr err = resolve_path(path, &resolved);
    if (err != PennFatErr_OK) {
        LOG_ERR("[k_rmdir] Path resolution failed for '%s' with error %d", path, err);
        return err;
    }

    if (!resolved.found) {
        LOG_ERR("[k_rmdir] Cannot remove directory '%s': Path does not exist.", path);
        return PennFatErr_EXISTS;
    }

    // 2. Check if it's a directory
    if (resolved.entry.type != 2) {
        LOG_ERR("[k_rmdir] Cannot remove '%s': Not a directory.", path);
        return PennFatErr_NOTDIR;
    }

    // 3. Check if the directory is empty (only '.' and '..' entries)
    uint16_t dir_block = resolved.entry.first_block;
    char *block_buffer = malloc(g_block_size);
    if (!block_buffer) {
        LOG_ERR("[k_rmdir] Failed to allocate memory for directory check.");
        return PennFatErr_OUTOFMEM;
    }

    if (read_block(block_buffer, dir_block) != 0) {
        LOG_ERR("[k_rmdir] Failed to read directory block %u.", dir_block);
        free(block_buffer);
        return PennFatErr_IO;
    }

    dir_entry_t *dir_entries = (dir_entry_t *)block_buffer;
    uint32_t entries_per_block = g_block_size / sizeof(dir_entry_t);
    bool is_empty = true;

    for (uint32_t i = 0; i < entries_per_block; i++) {
        if (dir_entries[i].name[0] == 0) {
            // End of directory
            break;
        }

        if ((uint8_t)dir_entries[i].name[0] == 1 || (uint8_t)dir_entries[i].name[0] == 2) {
            // Deleted entry, skip
            continue;
        }

        if (strcmp(dir_entries[i].name, ".") != 0 && strcmp(dir_entries[i].name, "..") != 0) {
            // Found a non-special entry, directory is not empty
            is_empty = false;
            break;
        }
    }

    free(block_buffer);

    if (!is_empty) {
        LOG_ERR("[k_rmdir] Cannot remove directory '%s': Directory not empty.", path);
        return PennFatErr_NOTEMPTY;
    }

    // 4. Remove the directory entry from the parent directory
    dir_entry_t deleted_entry;
    memset(&deleted_entry, 0, sizeof(dir_entry_t));
    deleted_entry.name[0] = 1; // Mark as deleted
    err = write_dirent(resolved.entry_block, resolved.entry_index_in_block, &deleted_entry);
    if (err != PennFatErr_OK) {
        LOG_ERR("[k_rmdir] Failed to mark directory entry as deleted (Error %d).", err);
        return err;
    }

    // 5. Free the directory block
    g_fat[dir_block] = FAT_FREE;

    LOG_INFO("[k_rmdir] Successfully removed directory '%s'.", path);
    return PennFatErr_OK;
}

// This function replaces the old k_rename implementation
PennFatErr k_rename(const char *oldpath, const char *newpath) {
     if (!g_mounted) {
        LOG_WARN("[k_rename] Failed to rename '%s' to '%s': Filesystem not mounted.", oldpath, newpath);
        return PennFatErr_NOT_MOUNTED;
    }
    if (!oldpath || oldpath[0] == '\0' || !newpath || newpath[0] == '\0') {
        LOG_ERR("[k_rename] Failed to rename: Invalid path(s).");
        return PennFatErr_INVAD;
    }
    if (strcmp(oldpath, newpath) == 0) {
        LOG_INFO("[k_rename] Source and destination paths are the same ('%s'). No operation performed.", oldpath);
        return PennFatErr_OK; // Nothing to do
    }
     LOG_INFO("[k_rename] Renaming '%s' to '%s'", oldpath, newpath);

    // 1. Resolve old path
    resolved_path_t old_resolved;
    PennFatErr err = resolve_path(oldpath, &old_resolved);
     if (err != PennFatErr_OK) {
        LOG_ERR("[k_rename] Path resolution failed for old path '%s' (Error %d)", oldpath, err);
        return err;
    }
     if (!old_resolved.found || old_resolved.is_root) {
         LOG_ERR("[k_rename] Cannot rename '%s': Source does not exist or is root.", oldpath);
         return PennFatErr_EXISTS;
     }
     // Prevent renaming '.' or '..' entries explicitly
     if (strcmp(old_resolved.entry.name, ".") == 0 || strcmp(old_resolved.entry.name, "..") == 0) {
          LOG_ERR("[k_rename] Cannot rename '.' or '..'.");
          return PennFatErr_INVAD;
     }

    // 2. Resolve new path (to check parent existence and if target exists)
    resolved_path_t new_resolved;
    err = resolve_path(newpath, &new_resolved);
    if (err != PennFatErr_OK && err != PennFatErr_NOTDIR) { // NOTDIR might be ok if target doesn't exist yet
        LOG_ERR("[k_rename] Path resolution failed for new path '%s' (Error %d)", newpath, err);
        return err;
    }

    // Check if new parent directory exists
    if (new_resolved.parent_dir_block == FAT_FREE || new_resolved.parent_dir_block == FAT_EOC) {
         LOG_ERR("[k_rename] Cannot rename to '%s': Parent directory does not exist.", newpath);
         return PennFatErr_EXISTS;
    }

    const char *new_filename = get_filename_from_path(newpath);
     if (!new_filename || strlen(new_filename) == 0 || strlen(new_filename) >= sizeof(old_resolved.entry.name)) {
         LOG_ERR("[k_rename] Invalid new filename derived from '%s'.", newpath);
         return PennFatErr_INVAD;
     }
      if (strcmp(new_filename, ".") == 0 || strcmp(new_filename, "..") == 0) {
          LOG_ERR("[k_rename] Cannot rename to '.' or '..'.");
          return PennFatErr_INVAD;
      }

     // 3. Handle if newpath already exists
     if (new_resolved.found) {
          // Cannot overwrite a directory with a non-directory or vice-versa without explicit flags (like rm -r)
          if (old_resolved.entry.type != new_resolved.entry.type) {
              LOG_ERR("[k_rename] Cannot rename '%s': Type mismatch with existing destination '%s'.", oldpath, newpath);
               return old_resolved.entry.type == 2 ? PennFatErr_NOTDIR : PennFatErr_ISDIR;
          }

         // Check permissions for overwrite (need write in new parent dir, and potentially write on existing file/dir)
         // (Skipping perm checks for now)

         // Unlink/rmdir the existing destination
         PennFatErr unlink_err;
         if (new_resolved.entry.type == 2) { // It's a directory
              unlink_err = k_rmdir(newpath); // Use k_rmdir for directories
             if (unlink_err != PennFatErr_OK) {
                  LOG_ERR("[k_rename] Failed to remove existing directory '%s' (Error %d).", newpath, unlink_err);
                 return unlink_err; // Propagate error (e.g., NOTEMPTY)
             }
         } else { // It's a file or symlink
              unlink_err = k_unlink(newpath); // Use k_unlink
             if (unlink_err != PennFatErr_OK) {
                  LOG_ERR("[k_rename] Failed to remove existing file/link '%s' (Error %d).", newpath, unlink_err);
                 return unlink_err; // Propagate error (e.g., BUSY)
             }
         }
         LOG_DEBUG("[k_rename] Successfully removed existing destination '%s'.", newpath);
     }

    // 4. Perform the rename
     // (Skipping permission checks on old parent and new parent for now)

    // Update the entry details we will write/move
    dir_entry_t entry_to_move = old_resolved.entry; // Copy the entry data
    strncpy(entry_to_move.name, new_filename, sizeof(entry_to_move.name) - 1);
    entry_to_move.name[sizeof(entry_to_move.name) - 1] = '\0';
    entry_to_move.mtime = time(NULL);


    // Add the entry to the new parent directory
    err = add_dirent_to_dir(new_resolved.parent_dir_block, &entry_to_move);
    if (err != PennFatErr_OK) {
        LOG_ERR("[k_rename] Failed to add entry for '%s' to new parent block %u (Error %d)", new_filename, new_resolved.parent_dir_block, err);
        // Rollback not possible easily here without more state.
        return err;
    }

    // Remove the old entry from the old parent directory
    dir_entry_t deleted_entry;
    memset(&deleted_entry, 0, sizeof(dir_entry_t));
    deleted_entry.name[0] = 1; // Mark as deleted
    err = write_dirent(old_resolved.entry_block, old_resolved.entry_index_in_block, &deleted_entry);
    if (err != PennFatErr_OK) {
        LOG_ERR("[k_rename] Failed to delete old entry for '%s' from block %u (Error %d). Filesystem potentially inconsistent.",
                 old_resolved.entry.name, old_resolved.entry_block, err);
        // Attempt rollback? Try removing the entry we just added to new parent? Difficult.
        // For now, return error but acknowledge inconsistency.
         return err;
    }


    LOG_INFO("[k_rename] Successfully renamed '%s' to '%s'.", oldpath, newpath);
    return PennFatErr_OK;
}

/*
 * Hierarchical Filesystem Implementation:
 * This implementation supports directories and subdirectories by treating
 * directories as special files that contain directory entries.
 * Each directory has its own block in the file system that contains
 * entries pointing to files and subdirectories.
 *
 * Navigation is handled through path resolution which walks the directory
 * tree from either the root (for absolute paths) or current working directory
 * (for relative paths).
 */

 PennFatErr k_getattr(const char *path, PennFatAttr *out)
 {
     if (!g_mounted)                      return PennFatErr_NOT_MOUNTED;
     if (!path || path[0] == '\0')        return PennFatErr_INVAD;
 
     resolved_path_t r;
     PennFatErr err = resolve_path(path, &r);
     if (err != PennFatErr_OK)            return err;
     if (!r.found)                        return PennFatErr_EXISTS;
 
     out->perm = r.entry.perm;
     return PennFatErr_OK;
 }