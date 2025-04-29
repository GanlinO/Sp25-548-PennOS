/******************************************************************************
 *                                                                            *
 *                             Author(s): Travis McGaha & Hannah Pan          *
 *                             Date(s):   04/17/20205 & 04/15/2021            *
 *                                                                            *
 ******************************************************************************/


 #include "stress.h"
 #include "../syscall/syscall_kernel.h"   /* s_spawn, s_waitpid, s_sleep, … */
#include "../common/pennfat_definitions.h" /* K_O_CREATE, K_O_WRONLY, …     */

 #include <stdbool.h>
 #include <stdio.h>
 #include <unistd.h>
 #include <stdlib.h> // for malloc
 #include <stdio.h>  // just for snprintf
 #include <signal.h> // for kill(SIGKILL) to mimic crashing for one of the tests
 #include <string.h> // for memcpy and strlen
 #include <time.h>   // for time()
 
 #define TELL(...)  dprintf(STDERR_FILENO, __VA_ARGS__)
 
 /******************************************************************************
  *                                                                            *
  * Replace syscalls.h with your own header file(s) for s_spawn and s_waitpid. *
  *                                                                            *
  ******************************************************************************/
 
 // #include "syscalls.h"
 
 
 
 // You can tweak the function signature to make it work.
 static void* nap(void* arg)
 {
     /* each child has a unique PID – perfect random seed        */
     unsigned seed = (unsigned)s_getselfpid();
     srand(seed);
 
     /* extra 0‥4 ticks, so total sleep = 1‥5 ticks               */
     clock_tick_t extra = rand() % 5;
     s_sleep(1 + extra);
 
     return NULL;
 }
 
 
 /*
  * The function below spawns 10 nappers named child_0 through child_9 and waits
  * on them. The wait is non-blocking if nohang is true, or blocking otherwise.
  *
  * You can tweak the function signature to make it work.
  */
 
 static void* spawn(bool nohang) {
   char name[] = "child_0";
   char *argv[] = { name, NULL };
   int pid = 0;
 
   // Spawn 10 nappers named child_0 through child_9.
   for (int i = 0; i < 10; i++) {
     argv[0][sizeof name - 2] = '0' + i;
 
     // you may need to change the args to
     // s_spawn for this to work.
     const int id = s_spawn(nap, argv, 0, 1);
 
     if (i == 0)
       pid = id;
     
     // may need to change the arg of the function to make it work
     // that is ok
     TELL("%s was spawned\n", argv[0]);
 
     // can use dprintf to test without integrating fat
     // dprintf(STDERR_FILENO, "%s was spawned\n", *argv);
   }
 
   // Wait on all children.
   while (1) {
     const int cpid = s_waitpid(-1, NULL, nohang);
 
     if (cpid < 0)  // no more waitable children (if block-waiting) or error
       break;
 
     // polling if nonblocking wait and no waitable children yet
     if (nohang && cpid == 0) {
       s_sleep(9);     // 9 ticks
       continue;
     }
 
     // snprintf is ok: it just prints to a string
     char child_num_str[4];
     snprintf(child_num_str, 4, "%d", cpid - pid);
     
     // may need to change the arg of the function to make it work
     // that is ok
     TELL("child_%d was reaped\n", cpid - pid);
 
     // can use dprintf to test without integrating fat
     // dprintf(STDERR_FILENO, "child_%d was reaped\n", cpid - pid);
   }
 
   return NULL;
 }
 
 
 /*
  * The function below recursively spawns itself 26 times and names the spawned
  * processes Gen_A through Gen_Z. Each process is block-waited by its parent.
  *
  * You can tweak the function signature to make it work.
  */
 
 static void* spawn_r(void* arg) {
   static int i = 0;
 
   int pid = 0;
   char name[] = "Gen_A";
   char *argv[] = { name, NULL };
 
   if (i < 26) {
     argv[0][sizeof name - 2] = 'A' + i++;
 
     // may need to change the arg of the function to make it work
     // that is ok
     pid = s_spawn(spawn_r, argv, 0, 1);
 
     // may need to change the arg of the function to make it work
     // that is ok
     TELL("%s was spawned\n", argv[0]);
 
     // can use dprintf to test without integrating fat
     // dprintf(STDERR_FILENO, "%s was spawned\n", *argv);
     
     s_sleep(1);  // 1 tick
   }
 
   if (pid > 0 && pid == s_waitpid(pid, NULL, false)) {
    TELL("%s was reaped\n", argv[0]);
     // dprintf(STDERR_FILENO, "%s was reaped\n", *argv);
   }
 
   return NULL;
 }
 
 static char* gen_pattern_str() {
   size_t len = 5480;
 
   char pattern[9];
   pattern[8] = '\0';
 
   srand(time(NULL));
 
   for (size_t i = 0; i < 8; i++) {
     // random ascii printable character
     pattern[i] = (char) ((rand() % 95) + 32);
   }
 
   char* str = malloc((len + 1) * sizeof(char));
   
   str[5480] = '\0';
 
   for (size_t i = 0; i < 5480; i += 8) {
     memcpy(&(str[i]), pattern, 8 * sizeof(char));
   }
 
   return str;
 
 }
 
 // you can change calls to s_write, s_unlink and s_open to match your implementation of these
 // functions if needed.
 static void crash_main() {
   const char *fname = "CRASHING.txt";
   s_unlink(fname);
 
   int fd = s_open(fname, K_O_CREATE | K_O_WRONLY);
 
   char* str = gen_pattern_str();
 
   const char* msg = "writing a string that consists of the following pattern 685 times to CRASHING.txt: ";
   s_write(STDERR_FILENO, msg, strlen(msg));
   s_write(STDERR_FILENO, str, 8);
   s_write(STDERR_FILENO, "\n", 1);
 
   // write the str to the file
   s_write(fd, str, 5480);
 
   msg = "crashing pennos. Our write should be safe in the file system.";
   s_write(STDERR_FILENO, msg, strlen(msg));
 
   msg = "We should see this file and this message in a hexdump of the fs\n";
   s_write(STDERR_FILENO, msg, strlen(msg));
 
   // Yes kill and signals are banned in PennOS.
   // The line below is an exception to mimic having pennos "crash"
   kill(0, SIGKILL);
 
   msg = "ERROR: PENNOS WAS SUPPOSED TO CRASH\n";
   s_write(STDERR_FILENO, msg, strlen(msg));
 }
 
 
 /******************************************************************************
  *                                                                            *
  * Add commands hang, nohang, recur, and crash to the shell as built-in       *
  * subroutines which call the following functions, respectively.              *
  *                                                                            *
  * you can change these function signautures as needed to make it work        *
  *                                                                            *
  ******************************************************************************/
 
 void* hang(void* arg) {
   spawn(false);
   return NULL;
 }
 
 void* nohang(void* arg) {
   spawn(true);
   return NULL;
 }
 
 void* recur(void* arg) {
   spawn_r(NULL);
   return NULL;
 }
 
 void* crash(void* arg) {
   // This one only works on a file system big enough to hold 5480 bytes
   crash_main();
   return NULL;
 }