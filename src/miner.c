#include "miner.h"

static int numgpu;
static int minergpus[MAX_OCL_DEV];
static int cgminerinstance;

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

static SOCKETTYPE send_data(char *command, int api_port)
{

	struct hostent *ip;
	struct sockaddr_in serv;
	SOCKETTYPE sock;

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
#ifdef HAVE_OPENCL
		if (SOCKETFAIL(send(sock, command, strlen(command), 0))) {
			pexit("API Send failed.\n");
		}
#endif
	}
	else
	{
		return INVSOCK;
	}

	return sock;
}

void miner_pause()
{
	SOCKETTYPE sock;
	char buf[SOCKET_BUFFER_LENGTH];

	char command[COMMAND_LENGTH];
	char *nextobj;
	int i;
	unsigned int dev_id;
	unsigned int platform_id;
	int api_port = cfg_get_int(SECTION_OPTIONS, SUBSECTION_MINER, "APIPort");

	cgminerinstance = 0;

	sock = send_data("gpucount", api_port);
	if (sock != INVSOCK)
	{
		cgminerinstance = 1;
		if (get_data(buf, sock))
		{
			nextobj = strchr(buf, '|');
			nextobj++;
			sscanf(nextobj, "GPUS,Count=%d|", &numgpu);
		}
	}
	CLOSESOCKET(sock);

#ifdef HAVE_OPENCL
	for (i = 0; i < numgpu; i++)
	{
		sprintf(command,"devdetails|%d", i);
		sock = send_data(command, api_port);
		if (sock != INVSOCK)
		{
			if (get_data(buf, sock))
			{
				nextobj = strchr(buf, '|');
				nextobj = strchr(buf, ',');
				nextobj = strchr(buf, ',');
				nextobj = strchr(buf, ',');
				nextobj++;
				sscanf(nextobj, "CL Platform ID=%d,CL Device ID=%d",
				    &platform_id, &dev_id);
				minergpus[i] = is_device_used(dev_id, platform_id);
				if (minergpus[i])
				{
					CLOSESOCKET(sock);
					sprintf(command,"gpudisable|%d", i);
					sock = send_data(command, api_port);
					if (sock == INVSOCK)
					{
						fprintf(stderr, "Error: Disabling device %d from platform %d.\n",
						    dev_id, platform_id);
					}
				}
			}
		}
		CLOSESOCKET(sock);
	}
#endif
}

void miner_start()
{
	if (cgminerinstance == 1)
	{
#ifdef HAVE_OPENCL
		int api_port = cfg_get_int(SECTION_OPTIONS, SUBSECTION_MINER, "APIPort");

		int i;
		int sock;
		char command[COMMAND_LENGTH];

		for (i = 0; i < numgpu; i++)
		{
			if (minergpus[i])
			{
				sprintf(command,"gpuenable|%d", i);
				sock = send_data(command, api_port);
				if (sock == INVSOCK)
				{
					fprintf(stderr, "Error: Renabling device %d from platform %d.\n",
					    get_device_id(minergpus[i]), get_platform_id(minergpus[i]));
				}
				CLOSESOCKET(sock);
			}
		}
#endif
	} else {
		if (cfg_get_int(SECTION_OPTIONS, SUBSECTION_MINER, "AfterEnd")) {
			char *Options = cfg_get_param(SECTION_OPTIONS, SUBSECTION_MINER, "AfterEndOptions");
			int i;
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
			i = 7;
			argv[i++] = strtok(Options, " ");
			while( (argv[i++] = strtok(NULL, " ")) != NULL );
			argv[i] = NULL;

			execv(dtach, argv);
		}
	}
}
