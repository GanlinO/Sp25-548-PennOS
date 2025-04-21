#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#include "util/utils.h"
#include "internal/pennfat_kernel.h"
#include "common/pennfat_definitions.h"
#include "common/pennfat_errors.h"

// ---------------------------------------------------------------------------
// x) DEFINITIONS
// ---------------------------------------------------------------------------

#define MAX_CMD_LENGTH 1024
#define BUFSIZE 4096

// Feel free to modify or not use this document
// this is just the skeleton of what stand alone pennfat
// will probably look like for you

// function declarations for special routines
static PennFatErr mkfs(const char *fs_name, int blocks_in_fat, int block_size_config);
static PennFatErr mount(const char *fs_name);
static PennFatErr unmount();
static PennFatErr ls();
static PennFatErr mv(const char *oldname, const char *newname);
static PennFatErr chmod(const char **args);
static PennFatErr cp(const char **args);

static void cat(const char **args);
static void rm(const char **args);
static void touch(const char** args);

// ---------------------------------------------------------------------------
// x) HELPER FUNCTIONS
// ---------------------------------------------------------------------------

int main(int argc, char *argv[]) {
    command_t *cmd;            // Parsed command structure
    char buf[MAX_CMD_LENGTH];  // Buffer for command input

    char **args;         // Arguments for the command
    PennFatErr status;   // Status of the command execution

    // Ignore SIGINT (Ctrl+C) and SIGTSTP (Ctrl+Z).
    signal(SIGINT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);

    // Initialize pennfat module
    pennfat_kernel_init();

    while (1) {
        prompt("pennfat# ");
        if (get_cmd(buf, MAX_CMD_LENGTH) == -1) {
            break;  // Exit on EOF
        }

        if (buf[0] == '\0') {
            continue; // Ignore empty lines
        }

        if (safe_parse_command(buf, &cmd)) {
            continue;
        }

        if (cmd->num_commands != 1 || cmd->commands[0] == NULL || cmd->commands[0][0] == NULL) {
            fprintf(stderr, "Unknown command\n");
            goto AFTER_EXECUTE;
        }

        args = cmd->commands[0];
        status = 0;

        if (strcmp(args[0], "mount") == 0) {
            /* mount */
            status = mount(args[1]);    
            if (status) {
                fprintf(stderr, "mount failed: %s\n", PennFatErr_toErrString(status));
            }

        } else if (strcmp(args[0], "unmount") == 0) {
            /* unmount */
            status = unmount();
            if (status) {
                fprintf(stderr, "unmount failed: %s\n", PennFatErr_toErrString(status));
            }

        } else if (strcmp(args[0], "mkfs") == 0) {
            /* mkfs */
            if (args[1] == NULL || args[2] == NULL || args[3] == NULL) {
                fprintf(stderr, "mkfs: missing arguments\n");
                goto AFTER_EXECUTE;
            }

            int blocks_in_fat = atoi(args[2]);
            int block_size_config = atoi(args[3]);

            if (blocks_in_fat < 1 || blocks_in_fat > 32) {
                fprintf(stderr, "Invalid number of blocks in FAT: %d\n", blocks_in_fat);
                goto AFTER_EXECUTE;
            }

            if (block_size_config < 0 || block_size_config > 4) {
                fprintf(stderr, "Invalid block size configuration: %d\n", block_size_config);
                goto AFTER_EXECUTE;
            }

            status = mkfs(args[1], blocks_in_fat, block_size_config);
            if (status) {
                fprintf(stderr, "mkfs failed: %s\n", PennFatErr_toErrString(status));
            }

        } else if (strcmp(args[0], "ls") == 0) {
            /* ls */
            status = ls();
            if (status) {
                fprintf(stderr, "ls failed: %s\n", PennFatErr_toErrString(status));
            }

        } else if (strcmp(args[0], "touch") == 0) {
            /* touch */
            if (args[1] == NULL) {
                fprintf(stderr, "touch: missing arguments\n");
                goto AFTER_EXECUTE;
            }
            touch((const char **)args + 1);

        } else if (strcmp(args[0], "mv") == 0) {
            /* mv */
            if (args[1] == NULL || args[2] == NULL) {
                fprintf(stderr, "mv: missing arguments\n");
                goto AFTER_EXECUTE;
            }

            status = mv(args[1], args[2]);
            if (status) {
                fprintf(stderr, "mv failed: %s\n", PennFatErr_toErrString(status));
            }

        } else if (strcmp(args[0], "rm") == 0) {
            /* rm */
            if (args[1] == NULL) {
                fprintf(stderr, "rm: missing arguments\n");
                goto AFTER_EXECUTE;
            }
            rm((const char **)args + 1);

        } else if (strcmp(args[0], "chmod") == 0) {
            /* chmod */
            if (args[1] == NULL || args[2] == NULL) {
                fprintf(stderr, "chmod: missing arguments\n");
                goto AFTER_EXECUTE;
            }

            status = chmod((const char **)args + 1);
            if (status) {
                fprintf(stderr, "chmod failed: %s\n", PennFatErr_toErrString(status));
            }

        } else if (strcmp(args[0], "cat") == 0) {
            /* cat */
            if (args[1] == NULL) {
                fprintf(stderr, "cat: missing arguments\n");
                goto AFTER_EXECUTE;
            }
            cat((const char **)args + 1);

        } else if (strcmp(args[0], "cp") == 0) {
            /* cp */
            if (args[1] == NULL || args[2] == NULL) {
                fprintf(stderr, "cp: missing arguments\n");
                goto AFTER_EXECUTE;
            }
            status = cp((const char **)args + 1);
            if (status) {
                fprintf(stderr, "cp failed: %s\n", PennFatErr_toErrString(status));
            }

        } else {
            fprintf(stderr, "pennfat: command not found: %s\n", args[0]);
        }

AFTER_EXECUTE:
        free(cmd);
    }

    // Cleanup
    pennfat_kernel_cleanup();

    return EXIT_SUCCESS;
}


// ---------------------------------------------------------------------------
// x) ROUTINE DEFINITIONS
// ---------------------------------------------------------------------------
static PennFatErr write_buffer(int out_fd, const char *buf, size_t length) {
    // Write using k_write if an output file descriptor was opened.
    if (out_fd >= 0) {
        PennFatErr ret = k_write(out_fd, buf, length);
        // Check that the write succeeded and that the entire buffer was written.
        if(ret < 0 || ((size_t)ret != length))
            return ret < 0 ? ret : -1;  // Return error if not fully written.
        return PennFatErr_SUCCESS;
    }

    // Otherwise, write to stdout using fwrite.
    size_t written = fwrite(buf, 1, length, stdout);
    return (written == length) ? PennFatErr_SUCCESS : -1;
}

/**
 * cat_command:
 *   cat FILE ... [ -w OUTPUT_FILE ]
 *   cat FILE ... [ -a OUTPUT_FILE ]
 *   cat -w OUTPUT_FILE
 *   cat -a OUTPUT_FILE
 */
static void cat(const char **args) {
    bool overwrite_mode = false;
    bool append_mode = false;
    const char *output_file = NULL;

    // An array to hold input file names; assume a maximum of 32 files.
    const char *input_files[32];
    int input_count = 0;

    // Parse arguments.
    for (int i = 0; args[i] != NULL; i++) {
        if (strcmp(args[i], "-w") == 0) {
            // Disallow multiple mode flags.
            if(overwrite_mode || append_mode) {
                fprintf(stderr, "cat: multiple output mode flags specified\n");
                return;
            }
            overwrite_mode = true;
            if(args[i + 1] == NULL) {
                fprintf(stderr, "cat: missing output file after -w\n");
                return;
            }
            output_file = args[++i];
        } else if (strcmp(args[i], "-a") == 0) {
            if(overwrite_mode || append_mode) {
                fprintf(stderr, "cat: multiple output mode flags specified\n");
                return;
            }
            append_mode = true;
            if(args[i + 1] == NULL) {
                fprintf(stderr, "cat: missing output file after -a\n");
                return;
            }
            output_file = args[++i];
        } else {
            if (input_count < 32) {
                input_files[input_count++] = args[i];
            } else {
                fprintf(stderr, "cat: too many input files\n");
                return;
            }
        }
    }

    // Open output file if specified.
    int out_fd = -1;  // If negative, we write to stdout.
    if (output_file) {
        // Choose open flags based on the mode.
        int open_flags = overwrite_mode ? (K_O_CREATE | K_O_WRONLY)
                                        : (K_O_CREATE | K_O_APPEND);
        PennFatErr ret = k_open(output_file, open_flags);
        if (ret < 0) {
            fprintf(stderr, "cat: error opening '%s': %s\n", output_file,
                    PennFatErr_toErrString(ret));
            return;
        }
        out_fd = ret;
        // For append mode, move the file offset to the end.
        if (append_mode) {
            ret = k_lseek(out_fd, 0, F_SEEK_END);
            if (ret < 0) {
                fprintf(stderr, "cat: error seeking end of '%s': %s\n",
                        output_file, PennFatErr_toErrString(ret));
                k_close(out_fd);
                return;
            }
        }
    }

    // Allocate a reusable buffer.
    char buffer[BUFSIZE];

    // If no input files are given, read from stdin.
    if (input_count == 0) {
        // Read only once
        if (fgets(buffer, BUFSIZE, stdin)) {
            size_t len = strlen(buffer);
            if (write_buffer(out_fd, buffer, len) != PennFatErr_SUCCESS) {
                fprintf(stderr, "cat: error writing output\n");
            }
        }
        if (ferror(stdin)) {
            perror("cat: error reading from stdin");
        }

        // If ctrl-D (EOF) is pressed, entire pennfat.c is terminated as we are
        // also reading from stdin for the command line.

    } else {
        // Process each input file.
        for (int i = 0; i < input_count; i++) {
            PennFatErr fd_or_err = k_open(input_files[i], K_O_RDONLY);
            if (fd_or_err < 0) {
                fprintf(stderr, "cat: error opening '%s'\n", input_files[i]);
                continue;  // Skip to the next file.
            }
            int in_fd = fd_or_err;
            while (true) {
                PennFatErr bytes_read = k_read(in_fd, BUFSIZE, buffer);
                if (bytes_read < 0) {
                    fprintf(stderr, "cat: read error in '%s'\n", input_files[i]);
                    break;
                }
                if (bytes_read == 0)
                    break;  // End of file reached.
                if (write_buffer(out_fd, buffer, bytes_read) != PennFatErr_SUCCESS) {
                    fprintf(stderr, "cat: error writing output for '%s'\n", input_files[i]);
                    break;
                }
            }
            k_close(in_fd);
        }
    }

    // Close output file if used
    if (out_fd >= 0) {
        k_close(out_fd);
    }
}

/**
 * cp command usage:
 *   cp [ -h ] SOURCE DEST
 *       -> Copies SOURCE (from PennOS filesystem or host OS if -h is given)
 *          to DEST in the PennOS filesystem.
 *   cp SOURCE -h DEST
 *       -> Copies SOURCE from the PennOS filesystem to DEST in the host OS.
 */
static PennFatErr cp(const char **args) {
    bool sourceFromHost = false;
    bool destToHost = false;
    const char *src_path = NULL;
    const char *dest_path = NULL;
    int arg_count = 0;

    // Count arguments (args is expected to be a NULL-terminated list)
    for (; args[arg_count] != NULL; arg_count++);

    // Acceptable usages:
    // 1. cp SOURCE DEST        (both in PennFAT)
    // 2. cp -h SOURCE DEST     (source from host OS; dest in PennFAT)
    // 3. cp SOURCE -h DEST     (source from PennFAT; dest in host OS)
    if (arg_count == 3) {
        if (strcmp(args[0], "-h") == 0) {
            sourceFromHost = true;
            src_path = args[1];
            dest_path = args[2];
        } else if (strcmp(args[1], "-h") == 0) {
            destToHost = true;
            src_path = args[0];
            dest_path = args[2];
        } else {
            fprintf(stderr, "cp: invalid flag usage. Use '-h' as the first argument to read from host or as the second to write to host.\n");
            return PennFatErr_INVAD;
        }
    } else if (arg_count == 2) {
        // No flag provided – both source and destination are in the PennFAT filesystem.
        src_path = args[0];
        dest_path = args[1];
    } else {
        fprintf(stderr, "Usage:\n  cp [ -h ] SOURCE DEST\n  cp SOURCE -h DEST\n");
        return -1;
    }

    char buffer[BUFSIZE];
    PennFatErr ret = PennFatErr_SUCCESS;

    if (sourceFromHost) {
        // Branch: Copying from host OS to PennOS filesystem.
        // Open the source using FILE operations.
        FILE *srcFile = fopen(src_path, "rb");
        if (!srcFile) {
            fprintf(stderr, "cp: error opening host source file '%s'\n", src_path);
            return -1;
        }

        // Open destination in the PennOS filesystem.
        int dest_fd = k_open(dest_path, K_O_CREATE | K_O_WRONLY);
        if (dest_fd < 0) {
            fprintf(stderr, "cp: error opening destination file '%s'\n", dest_path);
            fclose(srcFile);
            return dest_fd;
        }

        size_t bytesRead;
        while ((bytesRead = fread(buffer, 1, BUFSIZE, srcFile)) > 0) {
            PennFatErr bytesWritten = k_write(dest_fd, buffer, bytesRead);
            if (bytesWritten < 0 || (size_t)bytesWritten != bytesRead) {
                fprintf(stderr, "cp: error writing to '%s'\n", dest_path);
                ret = (bytesWritten < 0) ? bytesWritten : -1;
                break;
            }
        }

        if (ferror(srcFile)) {
            perror("cp: error reading host source file");
            ret = -1;
        }
        fclose(srcFile);
        k_close(dest_fd);
    } else if (destToHost) {
        // Branch: Copying from PennOS filesystem to host OS.
        // Open source file from PennOS.
        int src_fd = k_open(src_path, K_O_RDONLY);
        if (src_fd < 0) {
            fprintf(stderr, "cp: error opening source file '%s'\n", src_path);
            return src_fd;
        }

        // Open destination using FILE operations.
        FILE *destFile = fopen(dest_path, "wb");
        if (!destFile) {
            fprintf(stderr, "cp: error opening host destination file '%s'\n", dest_path);
            k_close(src_fd);
            return PennFatErr_INTERNAL;
        }
        while (1) {
            PennFatErr bytesRead = k_read(src_fd, BUFSIZE, buffer);
            if (bytesRead < 0) {
                fprintf(stderr, "cp: error reading from '%s'\n", src_path);
                ret = bytesRead;
                break;
            }
            if (bytesRead == 0) {
                ret = PennFatErr_SUCCESS;
                break;
            }
            size_t bytesWritten = fwrite(buffer, 1, bytesRead, destFile);
            if (bytesWritten != (size_t)bytesRead) {
                fprintf(stderr, "cp: error writing to '%s'\n", dest_path);
                ret = PennFatErr_INTERNAL;
                break;
            }
        }
        k_close(src_fd);
        fclose(destFile);
    } else {
        // Branch: Copying entirely within the PennOS filesystem.
        int src_fd = k_open(src_path, K_O_RDONLY);
        if (src_fd < 0) {
            fprintf(stderr, "cp: error opening source file '%s'\n", src_path);
            return src_fd;
        }
        int dest_fd = k_open(dest_path, K_O_CREATE | K_O_WRONLY);
        if (dest_fd < 0) {
            fprintf(stderr, "cp: error opening destination file '%s'\n", dest_path);
            k_close(src_fd);
            return dest_fd;
        }

        while (1) {
            PennFatErr bytesRead = k_read(src_fd, BUFSIZE, buffer);
            if (bytesRead < 0) {
                fprintf(stderr, "cp: error reading from '%s'\n", src_path);
                ret = bytesRead;
                break;
            }
            if (bytesRead == 0) {
                ret = PennFatErr_SUCCESS;
                break;
            }

            PennFatErr bytesWritten = k_write(dest_fd, buffer, bytesRead);
            if (bytesWritten < 0 || (size_t)bytesWritten != (size_t)bytesRead) {
                fprintf(stderr, "cp: error writing to '%s'\n", dest_path);
                ret = (bytesWritten < 0) ? bytesWritten : -1;
                break;
            }
        }
        k_close(src_fd);
        k_close(dest_fd);
    }

    return ret;
}

static PennFatErr mount(const char *fs_name) {
    return k_mount(fs_name);
}

static PennFatErr unmount() {
    return k_unmount();
}

static PennFatErr mkfs(const char *fs_name, int blocks_in_fat, int block_size_config) {
    return k_mkfs(fs_name, blocks_in_fat, block_size_config);
}

static void touch(const char** args) {
    int status;

    while (*args) {
        status = k_touch(*args);
        if (status) {
            fprintf(stderr, "touch failed for %s: %s\n", *args, PennFatErr_toErrString(status));
        }
        args++;
    }
}

static PennFatErr ls() {
    return k_ls();
}

static PennFatErr mv(const char *oldname, const char *newname) {
    return k_rename(oldname, newname);
}

static void rm(const char **args) {
    int status;

    while (*args) {
        status = k_unlink(*args);
        if (status) {
            fprintf(stderr, "rm failed for %s: %s\n", *args, PennFatErr_toErrString(status));
        }
        args++;
    }
}

static PennFatErr chmod(const char **args) {
    const char *perm_str = args[0];
    const char *fname = args[1];

    uint8_t perm = 0;
    if (strcmp(perm_str, "r") == 0) {
        perm = PERM_READ;
    } else if (strcmp(perm_str, "w") == 0) {
        perm = PERM_WRITE;
    } else if (strcmp(perm_str, "x") == 0) {
        perm = PERM_EXEC;
    } else if (strcmp(perm_str, "rw") == 0) {
        perm = PERM_READ | PERM_WRITE;
    } else if (strcmp(perm_str, "rx") == 0) {
        perm = PERM_READ | PERM_EXEC;
    } else if (strcmp(perm_str, "wx") == 0) {
        perm = PERM_WRITE | PERM_EXEC;
    } else if (strcmp(perm_str, "rwx") == 0) {
        perm = PERM_READ | PERM_WRITE | PERM_EXEC;
    } else {
        fprintf(stderr, "Invalid permission string: %s\n", perm_str);
        return PennFatErr_INVAD;
    }

    return k_chmod(fname, perm);
}
