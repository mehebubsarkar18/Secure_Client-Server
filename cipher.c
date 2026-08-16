#include "saes.h"

int encrypt(unsigned char *data, int len, int key)
{
    /* Add one padding byte if length is odd */
    if (len % 2 != 0)
    {
        data[len] = 0x00;
        len++;
    }

    for (int i = 0; i < len; i += 2)
    {
        uint16_t block =
            ((uint16_t)data[i] << 8) |
            data[i + 1];

        uint16_t cipher_block =
            saes_encrypt(block, (uint16_t)key);

        data[i] =
            (unsigned char)((cipher_block >> 8) & 0xFF);

        data[i + 1] =
            (unsigned char)(cipher_block & 0xFF);
    }

    return len;
}


int decrypt(unsigned char *data, int len, int key)
{
    for (int i = 0; i < len; i += 2)
    {
        uint16_t block =
            ((uint16_t)data[i] << 8) |
            data[i + 1];

        uint16_t plain_block =
            saes_decrypt(block, (uint16_t)key);

        data[i] =
            (unsigned char)((plain_block >> 8) & 0xFF);

        data[i + 1] =
            (unsigned char)(plain_block & 0xFF);
    }

    /* Remove padding */
    if (len > 0 && data[len - 1] == 0x00)
        len--;

    return len;
}