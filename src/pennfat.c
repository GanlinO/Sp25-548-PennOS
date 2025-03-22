#include "parser/parser.h"

// Feel free to modify or not use this document
// this is just the skeleton of what stand alone pennfat
// will probably look like for you

// function declarations for special routines
static void mkfs(const char *fs_name, int blocks_in_fat, int block_size_config);
static int mount(const char *fs_name);
static int unmount();

int main(int argc, char *argv[])
{
  // TODO: register signal handlers
  while (1)
  {
    // TODO: prompt, read command, parse command

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
