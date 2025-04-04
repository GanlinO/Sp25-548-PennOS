#include "../src/util/logger.h"

#include <stdio.h>
#include <stdlib.h>

static Logger *logger = NULL;


int main(void) {
    // Initialize a logger with the name "test_logger" and DEBUG level
    logger = logger_init("test_logger", LOG_LEVEL_DEBUG);
    if (logger == NULL) {
        fprintf(stderr, "Failed to initialize logger.\n");
        return EXIT_FAILURE;
    }

    // Log messages at different levels
    LOG_DEBUG("This is a debug message from the test logger.");
    LOG_INFO("This is an info message from the test logger.");
    LOG_WARN("This is a warning message from the test logger.");
    LOG_ERR("This is an error message from the test logger.");

    // Log a formatted message to test variable argument handling
    LOG_INFO("Testing formatted logging: %s, %d, %.2f", "string", 42, 3.14);

    // Close the logger to flush and release resources
    CLOSE_LOGGER();

    printf("Test complete. Check logs/test_logger.log for logged messages.\n");
    return EXIT_SUCCESS;
}
  