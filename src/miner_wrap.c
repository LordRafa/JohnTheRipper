#include "stdio.h"
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv) {

   char *argv1[] = {"cgminer", "-o", argv[0], "-u", argv[1], "-p", argv[2], argv[3], "--api-allow", "W:127.0.0.1/24", NULL};
   char *argv2[] = {"cgminer-api", NULL};
   char *envp[] = {NULL};

   pid_t pid;

   pid = fork();
   if (pid) {
     execve("./cgminer", argv1, envp);
   } else {
     execve("./cgminer-api", argv2, envp);
   }
   
   return 0;
}
