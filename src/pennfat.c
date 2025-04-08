#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#include "util/utils.h"
#include "internal/pennfat_kernel.h"
#include "common/pennfat_errors.h"

// ---------------------------------------------------------------------------
// x) DEFINITIONS
// ---------------------------------------------------------------------------

#define MAX_CMD_LENGTH 1024

// Feel free to modify or not use this document
// this is just the skeleton of what stand alone pennfat
// will probably look like for you

// function declarations for special routines
static PennFatErr mkfs(const char *fs_name, int blocks_in_fat, int block_size_config);
static PennFatErr mount(const char *fs_name);
static PennFatErr unmount();

// ---------------------------------------------------------------------------
// x) HELPER FUNCTIONS
// ---------------------------------------------------------------------------

static void signal_handler(int signum) {
    // Close logger
    pennfat_kernel_cleanup();
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
    command_t *cmd;            // Parsed command structure
    char buf[MAX_CMD_LENGTH];  // Buffer for command input

    char **args;         // Arguments for the command
    PennFatErr status;   // Status of the command execution

    // TODO: register signal handlers
    signal(SIGINT, signal_handler);

    // Initialize pennfat module
    pennfat_kernel_init();

    while (1) {
        prompt("pennfat# ");
        get_cmd(buf, MAX_CMD_LENGTH);

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

        } else {
            fprintf(stderr, "pennfat: command not found: %s\n", args[0]);
        }

AFTER_EXECUTE:
        free(cmd);
        


        // TODO: execute
        // char **args = parsed_command->commands[0];
        // if (strcmp(args[0], "ls") == 0)
        // {
        //   TODO: Call your implemented ls() function
        // }
        // else if (strcmp(args[0], "touch") == 0)
        // {
        //   TODO: Call your implemented touch() function
        // }
        // else if (strcmp(args[0], "cat") == 0)
        // {
        //   TODO: Call your implemented cat() function
        // }
        // else if (strcmp(args[0], "chmod") == 0)
        // {
        //   TODO: Call your implemented chmod() function
        // }
        // ...
        // 
        // else
        // {
        //   fprintf(stderr, "pennfat: command not found: %s\n", args[0]);
        // }
    }
    return EXIT_SUCCESS;
}


// ---------------------------------------------------------------------------
// x) ROUTINE DEFINITIONS
// ---------------------------------------------------------------------------
static PennFatErr mount(const char *fs_name) {
    return k_mount(fs_name);
}

static PennFatErr unmount() {
    return k_unmount();
}

static PennFatErr mkfs(const char *fs_name, int blocks_in_fat, int block_size_config) {
    return k_mkfs(fs_name, blocks_in_fat, block_size_config);
}
