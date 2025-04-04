#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdarg.h>

/* Define a LOG macro for convenience (defaulting to INFO level) */
#define LOG_DEBUG(fmt, ...) \
    do { \
        if (logger) { \
            logger_log(logger, LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_INFO(fmt, ...) \
    do { \
        if (logger) { \
            logger_log(logger, LOG_LEVEL_INFO, fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_WARN(fmt, ...) \
    do { \
        if (logger) { \
            logger_log(logger, LOG_LEVEL_WARN, fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_ERR(fmt, ...) \
    do { \
        if (logger) { \
            logger_log(logger, LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__); \
        } \
    } while (0)

/* Log levels definition */
typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR
} LogLevel;

/* Logger structure that holds file pointer, log level, and a name identifier */
typedef struct {
    FILE *fp;
    LogLevel level;
    char name[256];
} Logger;

/* 
 * Initializes a logger with a given name and log level.
 * The log file will be created in a "logs" directory as "name.log".
 * Returns a pointer to a Logger instance or NULL on failure.
 */
Logger* logger_init(const char* name, LogLevel level);

/*
 * Logs a message with the specified log level.
 * Only messages at or above the logger's level are written.
 */
void logger_log(Logger* logger, LogLevel level, const char* format, ...);

/*
 * Closes the logger and releases any associated resources.
 */
void logger_close(Logger* logger);

#endif // LOGGER_H
