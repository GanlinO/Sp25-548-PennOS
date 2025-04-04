#include "logger.h"
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

// This system call is used for logging purpose only.
#define MKDIR(dir) mkdir(dir, 0777)


/* 
 * Creates a logs directory if it does not already exist.
 */
static void create_log_dir(const char* dir) {
    MKDIR(dir);
}

Logger* logger_init(const char* name, LogLevel level) {
    Logger* logger = (Logger*)malloc(sizeof(Logger));
    if (!logger) {
        return NULL;
    }
    /* Copy the logger name and set the desired log level */
    strncpy(logger->name, name, sizeof(logger->name) - 1);
    logger->name[sizeof(logger->name) - 1] = '\0';
    logger->level = level;
    
    const char* log_dir = "logs";
    create_log_dir(log_dir);
    
    /* Construct the full file path for the log file */
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/%s.log", log_dir, name);
    
    logger->fp = fopen(file_path, "a");
    if (!logger->fp) {
        free(logger);
        return NULL;
    }
    return logger;
}

void logger_log(Logger* logger, LogLevel level, const char* format, ...) {
    if (!logger || !logger->fp) {
        return;
    }
    /* Only log messages at or above the current log level */
    if (level < logger->level) {
        return;
    }
    
    /* Get the current time for timestamping */
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    /* Map the log level to a string */
    const char *level_str;
    switch (level) {
        case LOG_LEVEL_DEBUG: level_str = "DEBUG"; break;
        case LOG_LEVEL_INFO:  level_str = "INFO";  break;
        case LOG_LEVEL_WARN:  level_str = "WARN";  break;
        case LOG_LEVEL_ERROR: level_str = "ERROR"; break;
        default: level_str = "INFO"; break;
    }
    
    /* Write the log header */
    fprintf(logger->fp, "[%s] %s [%s]: ", time_str, level_str, logger->name);
    
    /* Process the variable arguments and write the formatted message */
    va_list args;
    va_start(args, format);
    vfprintf(logger->fp, format, args);
    va_end(args);
    
    fprintf(logger->fp, "\n");
    fflush(logger->fp);
}

void logger_close(Logger* logger) {
    if (logger) {
        if (logger->fp) {
            fclose(logger->fp);
        }
        free(logger);
    }
}
