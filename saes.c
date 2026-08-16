#include "saes.h"

#define RCON1 0x80
#define RCON2 0x30

static const uint8_t sbox[16] =
{
    0x9, 0x4, 0xA, 0xB,
    0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3,
    0xC, 0xE, 0xF, 0x7
};

static const uint8_t inv_sbox[16] =
{
    0xA, 0x5, 0x9, 0xB,
    0x1, 0x7, 0x8, 0xF,
    0x6, 0x0, 0x2, 0x3,
    0xC, 0x4, 0xD, 0xE
};

static uint16_t sub_nib(uint16_t x)
{
    uint16_t result = 0;

    result |= sbox[(x >> 12) & 0xF] << 12;
    result |= sbox[(x >> 8) & 0xF] << 8;
    result |= sbox[(x >> 4) & 0xF] << 4;
    result |= sbox[x & 0xF];

    return result;
}

static uint16_t inv_sub_nib(uint16_t x)
{
    uint16_t result = 0;

    result |= inv_sbox[(x >> 12) & 0xF] << 12;
    result |= inv_sbox[(x >> 8) & 0xF] << 8;
    result |= inv_sbox[(x >> 4) & 0xF] << 4;
    result |= inv_sbox[x & 0xF];

    return result;
}

static uint16_t shift_rows(uint16_t state)
{
    uint16_t n0 = (state >> 12) & 0xF;
    uint16_t n1 = (state >> 8)  & 0xF;
    uint16_t n2 = (state >> 4)  & 0xF;
    uint16_t n3 = state & 0xF;

    return (n0 << 12) |
           (n1 << 8)  |
           (n3 << 4)  |
           n2;
}

static uint16_t inv_shift_rows(uint16_t state)
{
    return shift_rows(state);
}

static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t result = 0;

    while (b)
    {
        if (b & 1)
            result ^= a;

        a <<= 1;

        if (a & 0x10)
            a ^= 0x13;      // x⁴ + x + 1

        b >>= 1;
    }

    return result & 0xF;
}

static uint16_t mix_columns(uint16_t state)
{
    uint8_t s0 = (state >> 12) & 0xF;
    uint8_t s1 = (state >> 8)  & 0xF;
    uint8_t s2 = (state >> 4)  & 0xF;
    uint8_t s3 = state & 0xF;

    uint8_t t0 = s0 ^ gf_mul(4, s2);
    uint8_t t2 = gf_mul(4, s0) ^ s2;

    uint8_t t1 = s1 ^ gf_mul(4, s3);
    uint8_t t3 = gf_mul(4, s1) ^ s3;

    return (t0 << 12) |
           (t1 << 8) |
           (t2 << 4) |
           t3;
}

static uint16_t inv_mix_columns(uint16_t state)
{
    uint8_t s0 = (state >> 12) & 0xF;
    uint8_t s1 = (state >> 8)  & 0xF;
    uint8_t s2 = (state >> 4)  & 0xF;
    uint8_t s3 = state & 0xF;

    uint8_t t0 = gf_mul(9, s0) ^ gf_mul(2, s2);
    uint8_t t2 = gf_mul(2, s0) ^ gf_mul(9, s2);

    uint8_t t1 = gf_mul(9, s1) ^ gf_mul(2, s3);
    uint8_t t3 = gf_mul(2, s1) ^ gf_mul(9, s3);

    return (t0 << 12) |
           (t1 << 8) |
           (t2 << 4) |
           t3;
}

static uint8_t rot_nib(uint8_t x)
{
    return (x << 4) | (x >> 4);
}

static uint8_t sub_byte(uint8_t x)
{
    return (sbox[(x >> 4) & 0xF] << 4) |
           sbox[x & 0xF];
}

static void key_expansion(uint16_t key,
                          uint16_t roundKey[3])
{
    uint8_t w0 = (key >> 8) & 0xFF;
    uint8_t w1 = key & 0xFF;

    uint8_t w2 = w0 ^
                 RCON1 ^
                 sub_byte(rot_nib(w1));

    uint8_t w3 = w2 ^ w1;

    uint8_t w4 = w2 ^
                 RCON2 ^
                 sub_byte(rot_nib(w3));

    uint8_t w5 = w4 ^ w3;

    roundKey[0] = (w0 << 8) | w1;
    roundKey[1] = (w2 << 8) | w3;
    roundKey[2] = (w4 << 8) | w5;
}

static uint16_t add_round_key(uint16_t state,
    uint16_t key)
{
    return state ^ key;
}

uint16_t saes_encrypt(uint16_t plaintext, uint16_t key)
{
    uint16_t roundKey[3];
    uint16_t state = plaintext;

    key_expansion(key, roundKey);

    state = add_round_key(state, roundKey[0]);
    state = sub_nib(state);
    state = shift_rows(state);
    state = mix_columns(state);
    state = add_round_key(state, roundKey[1]);
    state = sub_nib(state);
    state = shift_rows(state);
    state = add_round_key(state, roundKey[2]);

    return state;
}

uint16_t saes_decrypt(uint16_t ciphertext, uint16_t key)
{
    uint16_t roundKey[3];
    uint16_t state = ciphertext;

    key_expansion(key, roundKey);

    state = add_round_key(state, roundKey[2]);
    state = shift_rows(state);
    state = inv_sub_nib(state);
    state = add_round_key(state, roundKey[1]);
    state = inv_mix_columns(state);
    state = inv_shift_rows(state);
    state = inv_sub_nib(state);
    state = add_round_key(state, roundKey[0]);

    return state;
}