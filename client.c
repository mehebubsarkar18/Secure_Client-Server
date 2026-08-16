#include "common.h"
#include "ecc.h"
#include "cipher.h"


typedef struct
{
    char username[USERNAME_LEN];
    char password[PASSWORD_LEN];
} LoginRequest;

static int send_all(SOCKET sock, const void *data, int length)
{
    int total = 0;
    const unsigned char *ptr = (const unsigned char *)data;

    while (total < length)
    {
        int sent = send(sock, (const char *)ptr + total,
            length - total, 0);

        if (sent == SOCKET_ERROR)
            return -1;

        total += sent;
    }

    return total;
}

static int recv_all(SOCKET sock, void *buffer, int length)
{
    int total = 0;
    unsigned char *ptr = (unsigned char *)buffer;

    while (total < length)
    {
        int received = recv(sock,
            (char *)ptr + total,
            length - total,
            0);

        if (received <= 0)
            return received;

        total += received;
    }

    return total;
}


static int send_packet(SOCKET sock,
    const unsigned char *data,
    int data_len)
{
    unsigned char header[4];

    header[0] = (data_len >> 24) & 0xFF;
    header[1] = (data_len >> 16) & 0xFF;
    header[2] = (data_len >> 8) & 0xFF;
    header[3] = data_len & 0xFF;

    if (send_all(sock, header, 4) != 4)
        return -1;

    return send_all(sock, data, data_len);
}
    static int recv_packet(SOCKET sock,
    unsigned char *buffer,
    int *data_len)
{
    unsigned char header[4];

    if (recv_all(sock, header, 4) != 4)
        return -1;

    *data_len =
        (header[0] << 24) |
        (header[1] << 16) |
        (header[2] << 8) |
        header[3];

    if (*data_len <= 0 || *data_len > MAX_MESSAGE)
        return -1;

    return recv_all(sock, buffer, *data_len);
}

int main(int argc, char *argv[])
{
    WSADATA wsa;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in serverAddr;
    unsigned char buffer[MAX_MESSAGE];
    char response[MAX_MESSAGE];
    LoginRequest login;
    int response_len;
    const char *server_ip = "127.0.0.1";
    int server_port = PORT;

    if (argc >= 2)
        server_ip = argv[1];
    if (argc >= 3)
        server_port = atoi(argv[2]);

    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0)
    {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
    {
        fprintf(stderr, "Socket creation failed\n");
        WSACleanup();
        return 1;
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(server_port);
    serverAddr.sin_addr.s_addr = inet_addr(server_ip);

    if (connect(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        fprintf(stderr, "Connection failed\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("Connected to server\n");

    printf("Username: ");
    scanf("%31s", login.username);
    printf("Password: ");
    scanf("%63s", login.password);

    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF);

    if (send_packet(sock, (unsigned char *)&login, sizeof(login)) != sizeof(login))
    {
        fprintf(stderr, "Failed to send login request\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    if (recv_packet(sock, (unsigned char *)response, &response_len) != response_len)
    {
        fprintf(stderr, "Server disconnected before authentication\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    response[response_len] = '\0';
    if (strcmp(response, "SUCCESS") != 0)
    {
        fprintf(stderr, "Authentication failed\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("Authentication successful\n");

    /* ===== ECC START ===== */

    int client_private = generate_private_key();
    Point client_public = generate_public_key(client_private);

    printf("\n===== CLIENT ECC =====\n");
    printf("Private Key : %d\n", client_private);
    printf("Public Key  : (%d,%d)\n",
       client_public.x,
       client_public.y);

    /* Send public key */

    PublicKeyPacket clientPkt;

    clientPkt.x = client_public.x;
    clientPkt.y = client_public.y;

    if (send_packet(sock,
        (unsigned char *)&clientPkt,
        sizeof(clientPkt)) != sizeof(clientPkt))
    {
    printf("Failed to send public key\n");

    closesocket(sock);
    WSACleanup();
    return 1;
    }

    /* Receive server public key */

    PublicKeyPacket serverPkt;

    if (recv_packet(sock,
                (unsigned char *)&serverPkt,
                &response_len) <= 0)
    {
    printf("Failed to receive server public key\n");

    closesocket(sock);
    WSACleanup();
    return 1;
    }

    Point server_public;

    server_public.x = serverPkt.x;
    server_public.y = serverPkt.y;
    server_public.infinity = 0;

/* Shared Secret */

    Point shared =
    generate_shared_secret(client_private,
                       server_public);

    printf("Shared Secret : (%d,%d)\n\n",
       shared.x,
       shared.y);

    int session_key = shared.x;
    printf("Session Key : %d\n\n", session_key);

    /* ===== ECC END ===== */

   while (1)
{
    printf("Client: ");

    if (!fgets((char *)buffer, MAX_MESSAGE - 1, stdin))
        break;

    int plaintext_len = (int)strlen((char *)buffer);

    if (plaintext_len == 0)
        continue;

    /* Show plaintext */
    printf("\nPlaintext : %s\n", buffer);

    /* Encrypt */
    int encrypted_len =
        encrypt(buffer, plaintext_len, session_key);

    /* Show encrypted message */
    printf("Ciphertext (Hex): ");

    for (int i = 0; i < encrypted_len; i++)
    {
        printf("%02X ", buffer[i]);
    }

    printf("\n");

    /* Send encrypted message */
    if (send_packet(sock, buffer, encrypted_len) != encrypted_len)
        break;

    /* Receive encrypted response */
    if (recv_packet(sock, buffer, &response_len) <= 0)
        break;

    /* Decrypt */
    int decrypted_len =
        decrypt(buffer, response_len, session_key);

    /* Add string terminator */
    buffer[decrypted_len] = '\0';

}

    closesocket(sock);
    WSACleanup();
    return 0;
}
