#include "miner.h"

static char numgpu;
static char minergpus[MAX_OCL_DEV];
static char cgminerinstance;

static int get_data(char *buf, SOCKETTYPE sock)
{
	int p, n;

	p = 0;
	buf[0] = '\0';
	while (p < SOCKET_BUFFER_LENGTH)
	{
		n = recv(sock, &buf[p], SOCKET_BUFFER_LENGTH - p , 0);
		if (SOCKETFAIL(n)) {
			pexit("API Recv failed.\n");
		}
		if (n == 0)
			break;
		p += n;
		buf[p] = '\0';
	}

	return 1;
}

void miner_pause()
{
	int api_port = cfg_get_int(SECTION_OPTIONS, SUBSECTION_MINER, "APIPort");

	struct hostent *ip;
	struct sockaddr_in serv;
	SOCKETTYPE sock;
	char buf[SOCKET_BUFFER_LENGTH];
	char command[COMMAND_LENGTH];
	char *nextobj;
	int i;
	unsigned int dev_id;
	unsigned int platform_id;

	cgminerinstance = 0;
	ip = gethostbyname("127.0.0.1");

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr = *((struct in_addr *)ip->h_addr);
	serv.sin_port = htons(api_port);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVSOCK)
	{
		pexit("Socket initialisation failed.\n");
	}

	if (!SOCKETFAIL(connect(sock, (struct sockaddr *)&serv, sizeof(struct sockaddr))))
	{
		cgminerinstance = 1;
#ifdef HAVE_OPENCL
		if (SOCKETFAIL(send(sock, "gpucount", strlen("gpucount"), 0))) {
			pexit("API Send failed.\n");
		}
		else
		{
			if (get_data(buf, sock))
			{
				nextobj = strchr(buf, '|');
				nextobj++;
				sscanf(nextobj, "GPUS,Count=%d|", &numgpu);
			}
		}
		close(sock);
#endif
	}

#ifdef HAVE_OPENCL
	for (i = 0; i < numgpu; i++)
	{
		sock = socket(AF_INET, SOCK_STREAM, 0);
		if (sock == INVSOCK)
		{
			pexit("Socket initialisation failed.\n");
		}

		if (!SOCKETFAIL(connect(sock, (struct sockaddr *)&serv, sizeof(struct sockaddr))))
		{
			sprintf(command,"devdetails|%d", i);
			if (SOCKETFAIL(send(sock, command, strlen(command), 0))) {
				pexit("API Send failed.\n");
			}
			else
			{
				if (get_data(buf, sock))
				{
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

	for (i = 0; i < numgpu; i++)
	{
		if (minergpus[i])
		{
			sock = socket(AF_INET, SOCK_STREAM, 0);
			if (sock == INVSOCK)
			{
				pexit("Socket initialisation failed.\n");
			}

			if (!SOCKETFAIL(connect(sock, (struct sockaddr *)&serv, sizeof(struct sockaddr))))
			{
				sprintf(command,"gpudisable|%d", i);
				if (SOCKETFAIL(send(sock, command, strlen(command), 0))) {
					pexit("API Send failed.\n");
				}
				close(sock);
			}
		}
	}

#endif
}

void miner_start()
{
	if (cgminerinstance == 1)
	{
#ifdef HAVE_OPENCL
		int api_port = cfg_get_int(SECTION_OPTIONS, SUBSECTION_MINER, "APIPort");

		int sock;
		char buf[SOCKET_BUFFER_LENGTH];
		char command[COMMAND_LENGTH];
		int i;
		struct hostent *ip;
		struct sockaddr_in serv;

		ip = gethostbyname("127.0.0.1");

		memset(&serv, 0, sizeof(serv));
		serv.sin_family = AF_INET;
		serv.sin_addr = *((struct in_addr *)ip->h_addr);
		serv.sin_port = htons(api_port);

		for (i = 0; i < numgpu; i++)
		{
			if (minergpus[i])
			{
				sock = socket(AF_INET, SOCK_STREAM, 0);
				if (sock == INVSOCK)
				{
					pexit("Socket initialisation failed.\n");
				}

				if (!SOCKETFAIL(connect(sock, (struct sockaddr *)&serv, sizeof(struct sockaddr))))
				{
					sprintf(command,"gpuenable|%d", i);
					if (SOCKETFAIL(send(sock, command, strlen(command), 0))) {
						pexit("API Send failed.\n");
					}
					close(sock);
				}
			}
		}
#endif
	} else {
		if (cfg_get_int(SECTION_OPTIONS, SUBSECTION_MINER, "AfterEnd")) {
			char *Options = cfg_get_param(SECTION_OPTIONS, SUBSECTION_MINER, "AfterEndOptions");

			char cgminer[PATH_BUFFER_SIZE];
			char dtach[PATH_BUFFER_SIZE];
			char *argv[MAX_PARAMS];

			strnzcpy(cgminer, path_expand(CGMINER_NAME), PATH_BUFFER_SIZE);
			strnzcpy(dtach, path_expand(DTACH_NAME), PATH_BUFFER_SIZE);

			argv[0] = dtach;
			argv[1] = "-n";
			argv[2] = "dtach_socket";
			argv[3] = cgminer;
			argv[4] = "--api-listen";
			argv[5] = "--api-allow";
			argv[6] = "W:127.0.0.1/24";
			int i = 7;
			argv[i++] = strtok(Options, " ");
			while( (argv[i++] = strtok(NULL, " ")) != NULL );
			argv[i] = NULL;

			execv(dtach, argv);
		}
	}
}
