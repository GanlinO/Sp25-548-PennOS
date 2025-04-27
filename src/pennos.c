/* src/pennos.c */

#include "internal/process_control.h"
#include "internal/pennfat_kernel.h"
#include "common/pennfat_errors.h"
#include "user/shell.h"
#include "util/logger.h"

#include <stdio.h>
#include <stdlib.h>

/* ─────────────────────────────────────────────── prototypes ─────────── */
static void print_welcome_banner(void);

/* ─────────────────────────────────────────────── entry point ─────────── */
int main(int argc, char *argv[])
{
    print_welcome_banner();

    /**********************************************************************
     * 1. (optional) CLI parsing – still TODO                             *
     *********************************************************************/
    const char *fs_image = "disk.img";          /* default while testing  */

    /**********************************************************************
     * 2.  PennFAT initialisation  +  “create-if-missing” mount           *
     *********************************************************************/
    pennfat_kernel_init();                      /* kernel-side structures */

    /* first try a normal mount … */
    PennFatErr err = k_mount(fs_image);

    if (err != PennFatErr_SUCCESS) {
        fprintf(stderr,
                "PennOS: %s is not a valid PennFAT image (%s). "
                "Creating a new one …\n",
                fs_image, PennFatErr_toErrString(err));

        /* format: 4 FAT blocks, block-size config 0 (512 B)               */
        const int FAT_BLOCKS = 4;
        const int BS_CFG     = 0;

        PennFatErr mkfs_err = k_mkfs(fs_image, FAT_BLOCKS, BS_CFG);
        if (mkfs_err != PennFatErr_SUCCESS) {
            fprintf(stderr,
                    "mkfs(%s) failed: %s\n",
                    fs_image, PennFatErr_toErrString(mkfs_err));
            exit(EXIT_FAILURE);
        }

        /* … and try the mount again                                      */
        err = k_mount(fs_image);
        if (err != PennFatErr_SUCCESS) {
            fprintf(stderr,
                    "Mount after mkfs still failed: %s\n",
                    PennFatErr_toErrString(err));
            exit(EXIT_FAILURE);
        }

        fprintf(stderr, "✓ New image created and mounted.\n");
    } else {
        fprintf(stderr, "✓ Mounted existing image %s\n", fs_image);
    }

    /**********************************************************************
     * 3.  start kernel + shell                                           *
     *********************************************************************/
    Logger *logger = logger_init_stderr(LOG_LEVEL_INFO, "KERNEL");
    k_set_logger(logger);

    fprintf(stderr, "Starting kernel …\n");
    char *args[] = { "shell", NULL };
    k_kernel_start(shell_main, args);           /* blocks until shutdown  */

    /**********************************************************************
     * 4.  unmount & cleanup                                              *
     *********************************************************************/
    k_unmount();
    pennfat_kernel_cleanup();

    fprintf(stderr, "PennOS shut down.  Goodbye!\n");
    return EXIT_SUCCESS;
}

/* ─────────────────────────────────────────────── banner (unchanged) ──── */
static void print_welcome_banner(void)
{
    /* …  your existing banner code … */
}
