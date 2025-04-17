#include "internal/process_control.h"       // internal kernel
#include "user/shell.h"

void print_welcome_banner();

int main(int argc, char *argv[]) {

  print_welcome_banner();

  /* PARSE AGRS FOR PENNFAT FILESYSTEM NAME AND LOG FILE NAME */
  // TODO

  /* MOUNT PENNFAT */
  // TODO

  /* RUN KERNEL (incl. INIT creation, run scheduler, spawn shell) */
  Logger* logger = logger_init_stderr(LOG_LEVEL_ERROR, "KERNEL");
  k_set_logger(logger);

  fprintf(stderr, "Starting kernel...\n");
  char* args[] = {"shell", NULL};
  k_kernel_start(shell_main, args);
  // this will keep running until shell shuts down, logger will also be closed

  /* CLEAN UP AND SHUT DOWN */
  // kernel cleanup handled inside k_kernel_start()

  fprintf(stderr, "PennOS shut down. Goodbye!\n");

}

void print_welcome_banner() {
  // ASCII art pattern credit: https://www.asciiart.eu/text-to-ascii-art

  #define RED_ON_BLUE "\033[0m\033[38;5;255m\033[48;5;25m"
  #define BLUE_ON_WHITE "\033[1m\033[38;5;124m\033[48;5;17m"

  fprintf(stderr, "\033[2J\033[H");
  fprintf(stderr, RED_ON_BLUE);
  fprintf(stderr, " ______  ______  ______  ______  ______  ______  ______  ______  ______  ______  ______  ______ \n");
  fprintf(stderr, "| |__| || |__| || |__| || |__| || |__| || |__| || |__| || |__| || |__| || |__| || |__| || |__| |\n");
  fprintf(stderr, "|  ()  ||  ()  ||  ()  ||  ()  ||  ()  ||  ()  ||  ()  ||  ()  ||  ()  ||  ()  ||  ()  ||  ()  |\n");
  fprintf(stderr, "|______||______||______||______||______||______||______||______||______||______||______||______|\n");
  fprintf(stderr, " ______   " BLUE_ON_WHITE "                                                                            " RED_ON_BLUE "   ______ \n");
  fprintf(stderr, "| |__| |" BLUE_ON_WHITE "       ,-.----.                                     ,----..                     " RED_ON_BLUE "| |__| |\n");
  fprintf(stderr, "|  ()  |" BLUE_ON_WHITE "       \\    /  \\                                   /   /   \\   .--.--.          " RED_ON_BLUE "|  ()  |\n");
  fprintf(stderr, "|______|" BLUE_ON_WHITE "       |   :    \\                                 /   .     : /  /    '.        " RED_ON_BLUE "|______|\n");
  fprintf(stderr, " ______ " BLUE_ON_WHITE "       |   |  .\\ :             ,---,      ,---,  .   /   ;.  \\  :  /`. /        " RED_ON_BLUE " ______ \n");
  fprintf(stderr, "| |__| |" BLUE_ON_WHITE "       .   :  |: |         ,-+-. /  | ,-+-. /  |.   ;   /  ` ;  |  |--`         " RED_ON_BLUE "| |__| |\n");
  fprintf(stderr, "|  ()  |" BLUE_ON_WHITE "       |   |   \\ : ,---.  ,--.'|'   |,--.'|'   |;   |  ; \\ ; |  :  ;_           " RED_ON_BLUE "|  ()  |\n");
  fprintf(stderr, "|______|" BLUE_ON_WHITE "       |   : .   //     \\|   |  ,\"' |   |  ,\"' ||   :  | ; | '\\  \\    `.        " RED_ON_BLUE "|______|\n");
  fprintf(stderr, " ______ " BLUE_ON_WHITE "       ;   | |`-'/    /  |   | /  | |   | /  | |.   |  ' ' ' : `----.   \\       " RED_ON_BLUE " ______ \n");
  fprintf(stderr, "| |__| |" BLUE_ON_WHITE "       |   | ;  .    ' / |   | |  | |   | |  | |'   ;  \\; /  | __ \\  \\  |       " RED_ON_BLUE "| |__| |\n");
  fprintf(stderr, "|  ()  |" BLUE_ON_WHITE "       :   ' |  '   ;   /|   | |  |/|   | |  |/  \\   \\  ',  / /  /`--'  /       " RED_ON_BLUE "|  ()  |\n");
  fprintf(stderr, "|______|" BLUE_ON_WHITE "       :   : :  '   |  / |   | |--' |   | |--'    ;   :    / '--'.     /        " RED_ON_BLUE "|______|\n");
  fprintf(stderr, " ______ " BLUE_ON_WHITE "       |   | :  |   :    |   |/     |   |/         \\   \\ .'    `--'---'         " RED_ON_BLUE " ______ \n");
  fprintf(stderr, "| |__| |" BLUE_ON_WHITE "       `---'.|   \\   \\  /'---'      '---'           `---`                       " RED_ON_BLUE "| |__| |\n");
  fprintf(stderr, "|  ()  |" BLUE_ON_WHITE "         `---`    `----'                                                        " RED_ON_BLUE "|  ()  |\n");
  fprintf(stderr, "|______|  " BLUE_ON_WHITE "                                                                            " RED_ON_BLUE "  |______|\n");
  fprintf(stderr, " ______  ______  ______  ______  ______  ______  ______  ______  ______  ______  ______  ______ \n");
  fprintf(stderr, "| |__| || |__| || |__| || |__| || |__| || |__| || |__| || |__| || |__| || |__| || |__| || |__| |\n");
  fprintf(stderr, "|  ()  ||  ()  ||  ()  ||  ()  ||  ()  ||  ()  ||  ()  ||  ()  ||  ()  ||  ()  ||  ()  ||  ()  |\n");
  fprintf(stderr, "|______||______||______||______||______||______||______||______||______||______||______||______|\n");

  fprintf(stderr, "\033[0m\n");
  fprintf(stderr, "\t\t\t\t       \033[1m\033[38;5;160m\033[4mWelcome to PennOS!\033[0m\n");
  fprintf(stderr, "\n\n");

  #undef RED_ON_BLUE
  #undef BLUE_ON_WHITE

}