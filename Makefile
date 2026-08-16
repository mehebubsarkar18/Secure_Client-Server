CC=gcc
CFLAGS=-I. -Wall -Wextra
LDFLAGS=-lws2_32

all: client.exe server.exe

client.exe: client.c crypto.c cipher.c ecc.c
	$(CC) $(CFLAGS) -o $@ client.c crypto.c cipher.c ecc.c $(LDFLAGS)

server.exe: server.c crypto.c cipher.c ecc.c
	$(CC) $(CFLAGS) -o $@ server.c crypto.c cipher.c ecc.c $(LDFLAGS)
