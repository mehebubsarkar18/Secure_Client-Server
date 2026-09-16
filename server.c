#include "ecc.h"
#include "common.h"
#include "cipher.h"
#include <process.h>

#define VALID_CLIENT_ID "client"
#define VALID_CLIENT_PASSWORD "password"
#define MAX_CLIENTS 64

volatile int g_server_should_exit = 0;
SOCKET g_listen_socket = INVALID_SOCKET;
SOCKET g_active_clients[MAX_CLIENTS];
int g_client_count = 0;

static void trim_line(char *text);

static void add_client_socket(SOCKET clientSocket)
{
    if (g_client_count < MAX_CLIENTS)
        g_active_clients[g_client_count++] = clientSocket;
}

static void remove_client_socket(SOCKET clientSocket)
{
    int i;

    for (i = 0; i < g_client_count; i++)
    {
        if (g_active_clients[i] == clientSocket)
        {
            for (int j = i; j < g_client_count - 1; j++)
                g_active_clients[j] = g_active_clients[j + 1];
            g_client_count--;
            break;
        }
    }
}

static void close_all_client_sockets(void)
{
    int i;

    for (i = 0; i < g_client_count; i++)
    {
        if (g_active_clients[i] != INVALID_SOCKET)
            closesocket(g_active_clients[i]);
    }

    g_client_count = 0;
}

static unsigned int __stdcall server_console_thread(void *arg)
{
    char command[64];
    (void)arg;

    while (!g_server_should_exit)
    {
        if (!fgets(command, sizeof(command), stdin))
            break;

        trim_line(command);

        if (strcmp(command, "BYE") == 0)
        {
            printf("Server requested disconnect. Closing active connections.\n");
            g_server_should_exit = 1;
            close_all_client_sockets();
            if (g_listen_socket != INVALID_SOCKET)
                closesocket(g_listen_socket);
            break;
        }
    }

    return 0;
}

// Send all bytes of a message over the socket.
static int send_all(SOCKET sock, const void *data, int length)
{
    int total = 0;
    const unsigned char *ptr = (const unsigned char *)data;

    while (total < length)
    {
        int sent = send(sock, (const char *)ptr + total, length - total, 0);
        if (sent == SOCKET_ERROR)
            return -1;
        total += sent;
    }
    return total;
}

// Receive a fixed number of bytes from the socket.
static int recv_all(SOCKET sock, void *buffer, int length)
{
    int total = 0;
    unsigned char *ptr = (unsigned char *)buffer;

    while (total < length)
    {
        int received = recv(sock, (char *)ptr + total, length - total, 0);
        if (received <= 0)
            return received;
        total += received;
    }
    return total;
}

// Send a framed message with a 4-byte length header.
static int send_packet(SOCKET sock, const unsigned char *data, int data_len)
{
    unsigned char header[4];
    header[0] = (unsigned char)((data_len >> 24) & 0xFF);
    header[1] = (unsigned char)((data_len >> 16) & 0xFF);
    header[2] = (unsigned char)((data_len >> 8) & 0xFF);
    header[3] = (unsigned char)(data_len & 0xFF);

    if (send_all(sock, header, 4) != 4)
        return -1;

    return send_all(sock, data, data_len);
}

// Read a framed message and extract its payload length.
static int recv_packet(SOCKET sock, unsigned char *buffer, int *data_len)
{
    unsigned char header[4];
    int bytes = recv_all(sock, header, 4);
    if (bytes <= 0)
        return bytes;

    *data_len = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];
    if (*data_len <= 0 || *data_len > MAX_MESSAGE)
        return -1;

    return recv_all(sock, buffer, *data_len);
}

static void trim_line(char *text)
{
    size_t len = strlen(text);

    while (len > 0 &&
        (text[len - 1] == '\n' || text[len - 1] == '\r'))
    {
        text[len - 1] = '\0';
        len--;
    }
}

static int send_encrypted_text(SOCKET sock,
    unsigned char *buffer,
    const char *text,
    int session_key)
{
    int plaintext_len = (int)strlen(text);
    int encrypted_len;

    if (plaintext_len <= 0 || plaintext_len >= MAX_MESSAGE)
        return -1;

    memcpy(buffer, text, plaintext_len);

    encrypted_len = encrypt(buffer, plaintext_len, session_key);

    if (send_packet(sock, buffer, encrypted_len) != encrypted_len)
        return -1;

    return encrypted_len;
}

static int authenticate_client(SOCKET clientSocket,
    unsigned char *buffer,
    int session_key)
{
    int recv_len;
    int decrypted_len;
    char *client_id;
    char *password;
    int authenticated = 0;

    if (recv_packet(clientSocket, buffer, &recv_len) <= 0)
        return 0;

    decrypted_len = decrypt(buffer, recv_len, session_key);
    buffer[decrypted_len] = '\0';

    client_id = (char *)buffer;
    password = strchr(client_id, '\n');

    if (password != NULL)
    {
        *password = '\0';
        password++;
        trim_line(client_id);
        trim_line(password);

        authenticated =
            strcmp(client_id, VALID_CLIENT_ID) == 0 &&
            strcmp(password, VALID_CLIENT_PASSWORD) == 0;
    }

    if (authenticated)
    {
        printf("Authentication successful for client ID: %s\n", client_id);

        if (send_encrypted_text(clientSocket,
            buffer,
            "AUTH_OK",
            session_key) < 0)
        {
            return 0;
        }

        return 1;
    }

    printf("Authentication failed\n");
    send_encrypted_text(clientSocket, buffer, "AUTH_FAIL", session_key);
    return 0;
}

// Handle one client connection in its own thread.
unsigned int __stdcall client_thread(void *arg)
{
    SOCKET clientSocket = (SOCKET)(intptr_t)arg;
    unsigned char buffer[MAX_MESSAGE];
    int recv_len;

/* ===== ECC KEY EXCHANGE ===== */

int server_private = generate_private_key();
Point server_public = generate_public_key(server_private);

printf("\n===== SERVER ECC =====\n");
printf("Private Key : %d\n", server_private);
printf("Public Key  : (%d,%d)\n",
       server_public.x,
       server_public.y);

/* Receive client public key */

PublicKeyPacket clientPkt;
int pktLen;

if (recv_packet(clientSocket,
                (unsigned char *)&clientPkt,
                &pktLen) <= 0)
{
    closesocket(clientSocket);
    return 0;
}

Point client_public;

client_public.x = clientPkt.x;
client_public.y = clientPkt.y;
client_public.infinity = 0;

/* Send server public key */

PublicKeyPacket serverPkt;

serverPkt.x = server_public.x;
serverPkt.y = server_public.y;

if (send_packet(clientSocket,
                (unsigned char *)&serverPkt,
                sizeof(serverPkt)) != sizeof(serverPkt))
{
    closesocket(clientSocket);
    return 0;
}

/* Shared secret */

Point shared =
generate_shared_secret(server_private,
                       client_public);

printf("Shared Secret : (%d,%d)\n",
       shared.x,
       shared.y);

int session_key = shared.x;

printf("Session Key : %d\n\n", session_key);

/* ===== END ECC ===== */

if (!authenticate_client(clientSocket, buffer, session_key))
{
        remove_client_socket(clientSocket);
        closesocket(clientSocket);
        return 0;
    }

    // Echo messages between the client and the server console.
    while (!g_server_should_exit)
    {
        if (recv_packet(clientSocket, buffer, &recv_len) <= 0)
            break;

        printf("\nCiphertext (Hex): ");

        for (int i = 0; i < recv_len; i++)
            printf("%02X ", buffer[i]);

        printf("\n");

        /* Decrypt */
        int decrypted_len =
            decrypt(buffer, recv_len, session_key);

        buffer[decrypted_len] = '\0';
        trim_line((char *)buffer);
        decrypted_len = (int)strlen((char *)buffer);

        printf("Plaintext : %s\n", buffer);

        if (strcmp((char *)buffer, "BYE") == 0)
        {
            printf("Client requested disconnect. Closing connection.\n");
            break;
        }

        /* Encrypt again before echoing */
        int encrypted_len =
            encrypt(buffer, decrypted_len, session_key);

        if (send_packet(clientSocket, buffer, encrypted_len) != encrypted_len)
            break;
    }

    remove_client_socket(clientSocket);
    closesocket(clientSocket);
    return 0;
}

// Main server entry point.
int main(void)
{
    WSADATA wsa;
    SOCKET listenSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddr;

    // Initialize Winsock.
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    // Create a listening TCP socket.
    listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET)
    {
        fprintf(stderr, "Socket creation failed\n");
        WSACleanup();
        return 1;
    }

    g_listen_socket = listenSocket;

    // Bind the socket to the chosen port and start listening.
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    if (bind(listenSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR ||
        listen(listenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        fprintf(stderr, "Bind/listen failed\n");
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    printf("Server listening on port %d\n", PORT);
    printf("Type BYE at the server console to terminate all connections.\n");

    uintptr_t consoleThread = _beginthreadex(NULL, 0, server_console_thread, NULL, 0, NULL);
    if (consoleThread)
        CloseHandle((HANDLE)consoleThread);

    while (!g_server_should_exit)
    {
        SOCKET clientSocket = accept(listenSocket, NULL, NULL);
        if (g_server_should_exit)
            break;
        if (clientSocket == INVALID_SOCKET)
            continue;

        add_client_socket(clientSocket);
        printf("Accepted new client\n");
        uintptr_t threadHandle = _beginthreadex(NULL, 0, client_thread, (void *)(intptr_t)clientSocket, 0, NULL);
        if (threadHandle)
            CloseHandle((HANDLE)threadHandle);
    }

    close_all_client_sockets();
    closesocket(listenSocket);
    g_listen_socket = INVALID_SOCKET;
    WSACleanup();
    return 0;
}
