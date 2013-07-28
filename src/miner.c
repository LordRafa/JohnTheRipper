/*
 * CGMiner integration.
 *
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013 by Lord Rafa.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include "miner.h"

static int numgpu = 0;
static int minergpus[MAX_OCL_DEV];
static int cgminerinstance;

static void get_data(char *buf, SOCKETTYPE sock)
{
	int p, n;

	p = 0;
	buf[0] = '\0';
	while (p < SOCKET_BUFFER_LENGTH)
	{
		n = recv(sock, &buf[p], SOCKET_BUFFER_LENGTH - p , 0);
		if (SOCKETFAIL(n)) {
			pexit("Error: API Recv failed.\n");
		}
		if (n == 0)
			break;
		p += n;
		buf[p] = '\0';
	}

}

static SOCKETTYPE send_data(char *command, int api_port)
{

	struct hostent *ip;
	struct sockaddr_in serv;
	SOCKETTYPE sock;

	if ((ip = gethostbyname(LOCALHOST)) == NULL) {
		pexit("Error: Couldn't find the host name.\n");
	}

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr = *((struct in_addr *)ip->h_addr);
	serv.sin_port = htons(api_port);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVSOCK)
	{
		pexit("Error: Socket initialisation failed.\n");
	}

	if (!SOCKETFAIL(connect(sock, (struct sockaddr *)&serv, sizeof(struct sockaddr))))
	{
#ifdef HAVE_OPENCL
		if (SOCKETFAIL(send(sock, command, strlen(command), 0))) {
			pexit("Error: API Send failed.\n");
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
	int api_port = cfg_get_int(SECTION_OPTIONS, SUBSECTION_MINER, CGMinerAPIPort);

	cgminerinstance = 0;

	sock = send_data(CGMinerAPIGPUCOUNT, api_port);
	if (sock != INVSOCK)
	{
		cgminerinstance = 1;
		get_data(buf, sock);
		if ((nextobj = strchr(buf, '|')) == NULL) {
			pexit("Error: Parsing CGMiner API.\n");
		}
		nextobj++;
		sscanf(nextobj, "GPUS,Count=%d|", &numgpu);
	}
	CLOSESOCKET(sock);

#ifdef HAVE_OPENCL
	for (i = 0; i < numgpu; i++)
	{
		sprintf(command,"%s|%d", CGMinerAPIDEVDETAILS, i);
		sock = send_data(command, api_port);
		if (sock != INVSOCK)
		{
			get_data(buf, sock);
			CLOSESOCKET(sock);
			if ((nextobj = strchr(buf, '|')) == NULL) {
				pexit("Error: Parsing CGMiner API.\n");
			}
			if ((nextobj = strchr(buf, ',')) == NULL) {
				pexit("Error: Parsing CGMiner API.\n");
			}
			if ((nextobj = strchr(buf, ',')) == NULL) {
				pexit("Error: Parsing CGMiner API.\n");
			}
			if ((nextobj = strchr(buf, ',')) == NULL) {
				pexit("Error: Parsing CGMiner API.\n");
			}
			nextobj++;
			sscanf(nextobj, "CL Platform ID=%d,CL Device ID=%d",
			    &platform_id, &dev_id);
			minergpus[i] = is_device_used(dev_id, platform_id);
			if (minergpus[i])
			{
				sprintf(command,"%s|%d", CGMinerAPIGPUDISABLE, i);
				sock = send_data(command, api_port);
				if (sock == INVSOCK)
				{
					fprintf(stderr, "Warning: Could not disabling device %d from platform %d.\n",
					    dev_id, platform_id);
				} else {
					CLOSESOCKET(sock);
				}
			}
		}
	}
#endif
}


void CGMinerGPURestart()
{
#ifdef HAVE_OPENCL
	int api_port = cfg_get_int(SECTION_OPTIONS, SUBSECTION_MINER, CGMinerAPIPort);

	int i;
	int sock;
	char command[COMMAND_LENGTH];

	for (i = 0; i < numgpu; i++)
	{
		if (minergpus[i])
		{
			sprintf(command,"%s|%d", CGMinerAPIGPUENABLE, i);
			sock = send_data(command, api_port);
			if (sock == INVSOCK)
			{
				fprintf(stderr, "Warning: Renabling device %d from platform %d.\n",
				get_device_id(minergpus[i]), get_platform_id(minergpus[i]));
			}
			CLOSESOCKET(sock);
		}
	}
#endif
}

void StartAfterEnd()
{
	if (cfg_get_int(SECTION_OPTIONS, SUBSECTION_MINER, AFTEREND)) {
		char *Options = cfg_get_param(SECTION_OPTIONS, SUBSECTION_MINER, AFTERENDPARAMS);
		int i;
		char cgminer[PATH_BUFFER_SIZE];
		char dtach[PATH_BUFFER_SIZE];
		char *argv[MAX_PARAMS];

		strnzcpy(cgminer, path_expand(CGMINER_NAME), PATH_BUFFER_SIZE);
		strnzcpy(dtach, path_expand(DTACH_NAME), PATH_BUFFER_SIZE);

		argv[0] = dtach;
		argv[1] = DTACHMODEDETACHED;
		argv[2] = DTACHSOCKETFILE
		argv[3] = cgminer;
		argv[4] = CGMinerParamAPILISTEN;
		argv[5] = CGMinerParamAPIALLOW;
		argv[6] = CGMinerParamAPIALLOWIP;
		i = 7;
		argv[i++] = strtok(Options, " ");
		while( (argv[i++] = strtok(NULL, " ")) != NULL );
		argv[i] = NULL;

		if (execv(dtach, argv) == -1)
			fprintf(stderr, "Warning: CGMiner could not be executed.\n");
	}
}

void miner_start()
{
	if (cgminerinstance == 1)
	{
		CGMinerGPURestart();
	} else {
		StartAfterEnd();
	}
}
