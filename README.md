for compilation:
    gcc -I. -Wall -Wextra -o client.exe client.c cipher.c ecc.c saes.c -lws2_32
    gcc -I. -Wall -Wextra -o server.exe server.c cipher.c ecc.c saes.c -lws2_32