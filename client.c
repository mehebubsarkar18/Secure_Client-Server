#include "common.h"
#include "ecc.h"
#include "cipher.h"

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

static int read_required_line(const char *prompt,
    char *buffer,
    size_t buffer_size)
{
    while (1)
    {
        printf("%s", prompt);

        if (!fgets(buffer, (int)buffer_size, stdin))
            return 0;

        trim_line(buffer);

        if (buffer[0] != '\0')
            return 1;

        printf("Please enter a value.\n");
    }
}

static int read_port_number(void)
{
    char input[32];

    while (1)
    {
        char *end = NULL;
        long port;

        if (!read_required_line("Enter server port number: ",
            input,
            sizeof(input)))
        {
            return -1;
        }

        port = strtol(input, &end, 10);

        if (end != input && *end == '\0' && port > 0 && port <= 65535)
            return (int)port;

        printf("Please enter a valid port number (1-65535).\n");
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

int main(void)
{
    WSADATA wsa;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in serverAddr;
    unsigned char buffer[MAX_MESSAGE];
    int response_len;
    char server_ip[64];
    int server_port;

    if (!read_required_line("Enter server IP address: ",
        server_ip,
        sizeof(server_ip)))
    {
        return 1;
    }

    server_port = read_port_number();
    if (server_port < 0)
        return 1;

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
    if (serverAddr.sin_addr.s_addr == INADDR_NONE)
    {
        fprintf(stderr, "Invalid IP address\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        fprintf(stderr, "Connection failed\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("Connected to server\n");

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

    char client_id[64];
    char password[64];
    char auth_message[MAX_MESSAGE];

    if (!read_required_line("Client ID: ", client_id, sizeof(client_id)) ||
        !read_required_line("Password: ", password, sizeof(password)))
    {
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    if (snprintf(auth_message,
        sizeof(auth_message),
        "%s\n%s",
        client_id,
        password) >= (int)sizeof(auth_message))
    {
        fprintf(stderr, "Authentication data is too long\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    if (send_encrypted_text(sock,
        buffer,
        auth_message,
        session_key) < 0)
    {
        fprintf(stderr, "Failed to send authentication data\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    if (recv_packet(sock, buffer, &response_len) <= 0)
    {
        fprintf(stderr, "Failed to receive authentication response\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    int auth_response_len =
        decrypt(buffer, response_len, session_key);

    buffer[auth_response_len] = '\0';

    if (strcmp((char *)buffer, "AUTH_OK") != 0)
    {
        printf("Authentication failed. Connection closed.\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("Authentication successful.\nType BYE to close the connection.\n\n");

   while (1)
{
    printf("Client: ");

    if (!fgets((char *)buffer, MAX_MESSAGE - 1, stdin))
        break;

    trim_line((char *)buffer);

    int plaintext_len = (int)strlen((char *)buffer);

    if (plaintext_len == 0)
        continue;

    int should_close = strcmp((char *)buffer, "BYE") == 0;

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

    if (should_close)
    {
        printf("Closing connection.\n");
        break;
    }

}

    closesocket(sock);
    WSACleanup();
    return 0;
}
