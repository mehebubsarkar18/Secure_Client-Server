#ifndef SAES_H
#define SAES_H

#include <stdint.h>

uint16_t saes_encrypt(uint16_t plaintext, uint16_t key);
uint16_t saes_decrypt(uint16_t ciphertext, uint16_t key);

#endif