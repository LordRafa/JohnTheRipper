#ifndef miner_h
#define miner_h

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>

#ifdef HAVE_OPENCL
#include "common-opencl.h"
#endif

int miner_pause();
void miner_start(int miner);

#endif