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

#ifndef miner_h
#define miner_h

#include <stdio.h>
#include <unistd.h>

#include "config.h"
#include "params.h"

#ifdef HAVE_OPENCL
#include "common-opencl.h"
#endif

#define MAX_OCL_DEV 256
#define MAX_PARAMS 256
#define COMMAND_LENGTH 256
#define SOCKET_BUFFER_LENGTH 4096

#if defined(unix)
	#include <errno.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <netdb.h>

	#define SOCKETTYPE int
	#define SOCKETFAIL(a) ((a) < 0)
	#define INVSOCK -1
	#define CLOSESOCKET close
#endif

#ifdef WIN32
	#include <winsock2.h>

	#define SOCKETTYPE SOCKET
	#define SOCKETFAIL(a) ((a) == SOCKET_ERROR)
	#define INVSOCK INVALID_SOCKET
	#define CLOSESOCKET closesocket
#endif

void miner_pause();
void miner_start();

#endif
