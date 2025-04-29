// ─── src/pennos.c ────────────────────────────────────────────
//  PennOS kernel bootstrap & PennFAT integration
//  (updated to satisfy spec §5 – fatfs image + optional log file)
// -------------------------------------------------------------------
#include "../internal/process_control.h"          // k_kernel_start …
#include "../internal/pennfat_kernel.h"           // k_mount / k_mkfs …
#include "../util/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

/* ------------------------------------------------------------------ */
/*                      command‑line processing                       */
/* ------------------------------------------------------------------ */
static const char *fatfs_path = NULL;    /* mandatory */
static const char *log_path   = "pennos";  /* default   */

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s fatfs [log_fname]\n"
            "        fatfs      – host‑file that *contains* the PennFAT image\n"
            "        log_fname  – host‑side log file (default: ./log)\n",
            prog);
    exit(EXIT_FAILURE);
}

static void parse_args(int argc, char **argv)
{
    if (argc < 2 || argc > 3)
        usage(argv[0]);

    fatfs_path = argv[1];
    if (argc == 3) log_path = argv[2];
}

/* ------------------------------------------------------------------ */
/*                             utilities                             */
/* ------------------------------------------------------------------ */
static void ensure_image_exists(void)
{
    struct stat st;
    if (stat(fatfs_path, &st) == 0) return;          /* already there */

    fprintf(stderr, "[%s] image not found – creating new PennFAT FS …\n",
            fatfs_path);
    PennFatErr e = k_mkfs(fatfs_path, /*blocks_in_fat*/100, /*blk_size*/4096);
    if (e != PennFatErr_OK) {
        fprintf(stderr, "mkfs(%s) failed: %d\n", fatfs_path, e);
        exit(EXIT_FAILURE);
    }
}

/* ------------------------------------------------------------------ */
/*                         program entry‑point                        */
/* ------------------------------------------------------------------ */
extern void *shell_main(void *arg);   /* defined in shell.c */

int main(int argc, char **argv)
{
    /* ➊ parse CLI -------------------------------------------------- */
    parse_args(argc, argv);

    /* ➋ host‑side logger ------------------------------------------ */
    logger_init(log_path, LOG_LEVEL_INFO);   // writes on the host FS

    /* ➌ PennFAT bootstrap ----------------------------------------- */
    pennfat_kernel_init();                   // core structures
    ensure_image_exists();
    if (k_mount(fatfs_path) != PennFatErr_OK) {
        fprintf(stderr, "cannot mount %s: %s\n", fatfs_path, strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* ➍ launch kernel scheduler + shell --------------------------- */
    k_kernel_start(shell_main, NULL);

    /* ➎ graceful shutdown ----------------------------------------- */
    k_unmount();
    pennfat_kernel_cleanup();
    logger_close(NULL);
    return 0;
}
