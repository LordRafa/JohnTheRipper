#include "miner.h"


char numgpu;
char minergpus[256];
char cgminerinstance;

#ifdef __linux__
int get_data(char *buf, int sock)
{
   int p, n;
   
   p = 0;
   buf[0] = '\0';
   while (p < 4096) {
      n = recv(sock, &buf[p], 4096 - p , 0);
      if (n<0) {
         return 0;
      }
      if (n == 0)
         break;

      p += n;
      buf[p] = '\0';
   }

   return 1;
}
#endif

int miner_pause()
{
#ifdef __linux__
   char *miner_api_port = cfg_get_int(SECTION_OPTIONS, SUBSECTION_MINER, "MinerAPIPort");
   struct hostent *ip;
   struct sockaddr_in serv;
   int sock;
   char buf[4096];
   char command[256];
   char *nextobj;
   int i;
   unsigned int dev_id;
   unsigned int platform_id;


   cgminerinstance = 0;
   ip = gethostbyname("127.0.0.1");

   memset(&serv, 0, sizeof(serv));
   serv.sin_family = AF_INET;
   serv.sin_addr = *((struct in_addr *)ip->h_addr);
   serv.sin_port = htons(miner_api_port);

   sock = socket(AF_INET, SOCK_STREAM, 0);
   if (sock == -1) {
      printf("Socket initialisation failed.\n");
   }   
   if (connect(sock, (struct sockaddr *)&serv, sizeof(struct sockaddr)) >= 0) {
      cgminerinstance = 1;
#ifdef HAVE_OPENCL
      if (!(send(sock, "gpucount", strlen("gpucount"), 0) < 0)) {
         if (get_data(buf, sock)) {
            nextobj = strchr(buf, '|');
            nextobj++;
            sscanf(nextobj, "GPUS,Count=%d|", &numgpu);
         }         
      }
      close(sock);
#endif
   }

#ifdef HAVE_OPENCL
   for (i = 0; i < numgpu; i++) {
      sock = socket(AF_INET, SOCK_STREAM, 0);
      if (sock == -1) {
         printf("Socket initialisation failed.\n");
      }
      if (connect(sock, (struct sockaddr *)&serv, sizeof(struct sockaddr)) >= 0) {
         sprintf(command,"devdetails|%d", i);
         if (!(send(sock, command, strlen(command), 0) < 0)) {
            if (get_data(buf, sock)) {
               nextobj = strchr(buf, '|');
               nextobj = strchr(buf, ',');
               nextobj = strchr(buf, ',');
               nextobj = strchr(buf, ',');
               nextobj++;
               sscanf(nextobj, "CL Platform ID=%d,CL Device ID=%d", &platform_id, &dev_id);
               minergpus[i] = get_sequential_id(dev_id, platform_id) != -1;
            }
         }
         close(sock);
      }
   }

   for (i = 0; i < numgpu; i++) {
      if (minergpus[i]) {
         sock = socket(AF_INET, SOCK_STREAM, 0);
         if (sock == -1) {
            printf("Socket initialisation failed.\n");
         }
         if (connect(sock, (struct sockaddr *)&serv, sizeof(struct sockaddr)) >= 0) {
            sprintf(command,"gpudisable|%d", i);
            send(sock, command, strlen(command), 0);
            close(sock);
         }
      }
   }
#endif
#endif
   
   return 0;
}

void miner_start(int miner)
{
#ifdef __linux__
   if (cgminerinstance == 1) {
      #ifdef HAVE_OPENCL
      char *miner_api_port = cfg_get_int(SECTION_OPTIONS, SUBSECTION_MINER, "MinerAPIPort");
      int sock;
      char buf[4096];
      char command[256];
      int i;
      struct hostent *ip;
      struct sockaddr_in serv;
      
      ip = gethostbyname("127.0.0.1");

      memset(&serv, 0, sizeof(serv));
      serv.sin_family = AF_INET;
      serv.sin_addr = *((struct in_addr *)ip->h_addr);
      serv.sin_port = htons(miner_api_port);
      for (i = 0; i < numgpu; i++) {
         if (minergpus[i]) {
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock == -1) {
               printf("Socket initialisation failed.\n");
            }
            if (connect(sock, (struct sockaddr *)&serv, sizeof(struct sockaddr)) >= 0) {
               sprintf(command,"gpuenable|%d", i);
               send(sock, command, strlen(command), 0);
               close(sock);
            }
         }
      }
      #endif
   } else {
      if (cfg_get_int(SECTION_OPTIONS, SUBSECTION_MINER, "MinerAfterEnd"))
         miner = 1;
      
      if (miner) {         
         char *miner_pool_url = cfg_get_param(SECTION_OPTIONS, SUBSECTION_MINER, "MinerPoolURL");
         char *miner_pool_usr = cfg_get_param(SECTION_OPTIONS, SUBSECTION_MINER, "MinerPoolUSR");
         char *miner_pool_pwd = cfg_get_param(SECTION_OPTIONS, SUBSECTION_MINER, "MinerPoolPWD");
         char *miner_api_port = cfg_get_param(SECTION_OPTIONS, SUBSECTION_MINER, "MinerAPIPort");
         char *miner_platform = cfg_get_param(SECTION_OPTIONS, SUBSECTION_MINER, "MinerPlatform");

         char *envp[] = {"TERM=xterm", NULL};
         char *argv[] = {"./cgminer",
            "-o", miner_pool_url,
            "-u", miner_pool_usr,
            "-p", miner_pool_pwd,
            "--api-port", miner_api_port,
            "--api-listen", "--api-allow", "W:127.0.0.1/24", 
            miner_platform,
            NULL
         };

         execve("./cgminer", argv, envp);
      }
   }
#endif
}
 
