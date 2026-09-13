#ifndef COMMON_H
#define COMMON_H

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PORT 8080
#define MAX_MESSAGE 1024

typedef struct {
    int x;
    int y;
} PublicKeyPacket;

#endif
