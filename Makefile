CC=gcc
CFLAGS=-I. -Wall -Wextra
LDFLAGS=-lws2_32

all: client.exe server.exe

client.exe: client.c cipher.c ecc.c saes.c
	$(CC) $(CFLAGS) -o $@ client.c cipher.c ecc.c saes.c $(LDFLAGS)

server.exe: server.c cipher.c ecc.c saes.c
	$(CC) $(CFLAGS) -o $@ server.c cipher.c ecc.c saes.c $(LDFLAGS)
