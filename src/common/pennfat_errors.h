#ifndef PENNFAT_ERRORS_H
#define PENNFAT_ERRORS_H

enum PennFatErr
{
    PennFatErr_SUCCESS      = 0,
    PennFatErr_OK           = 0,  // Alias for SUCCESS
    PennFatErr_INTERNAL     = -1,
    PennFatErr_NOT_MOUNTED  = -2,
    PennFatErr_INVAD        = -3,
    PennFatErr_EXISTS       = -4,
    PennFatErr_PERM         = -5,
    PennFatErr_INUSE        = -6,
    PennFatErr_NOSPACE      = -7,
    PennFatErr_OUTOFMEM     = -8,
    PennFatErr_UNEXPCMD     = -9,
    PennFatErr_NOTEMPTY     = -10, // Directory not empty
    PennFatErr_NOTDIR       = -12, // Not a directory
    PennFatErr_ISDIR        = -13, // Is a directory
    PennFatErr_IO           = -14, // I/O error
    PennFatErr_BUSY         = -15, // Resource busy
    PennFatErr_NOT_IMPL     = -16, // Not implemented
    PennFatErr_RANGE        = -17, // Range error (buffer too small, etc.)
    PennFatErr_DUMMY        = -18  // Dummy as PENNFAT_ERR_MIN for scalar range
};
typedef enum PennFatErr PennFatErr;

#define PENNFAT_ERR_MIN   (PennFatErr_DUMMY)  /* -18 */
#define PENNFAT_ERR_MAX   (PennFatErr_SUCCESS)  /* 0 */
#define PENNFAT_ERR_COUNT (PENNFAT_ERR_MAX - PENNFAT_ERR_MIN + 1)  /* 0 - (-18) + 1 = 19 */

static const char * const pennFatErrStrings[PENNFAT_ERR_COUNT] = {
    "Dummy error",
    "Range error",
    "Not implemented",
    "Resource busy",
    "I/O error",
    "Is a directory",
    "Not a directory",
    "Directory not empty",
    "Unexpected command",
    "Out of memory",
    "No space left on device",
    "File in use",
    "Permission denied",
    "File existance error",
    "Invalid argument",
    "File system not mounted",
    "Internal error",
    "Success",
    "Success"
};

static inline const char *PennFatErr_toErrString(PennFatErr err)
{
    int index = err - PENNFAT_ERR_MIN + 1;  /* For example, if err is -1: -1 - (-9) = 8 */
    if (index >= 0 && index < PENNFAT_ERR_COUNT)
       return pennFatErrStrings[index];

    return "Unknown error";
}

#endif /* PENNFAT_ERRORS_H */