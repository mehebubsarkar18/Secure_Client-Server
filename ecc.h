#ifndef ECC_H
#define ECC_H

#include "common.h"

typedef struct
{
    int x;
    int y;
    int infinity;
} Point;

/* Elliptic curve parameters */
#define PRIME 97
#define A 2
#define B 3

/* Generator order is 50, so private key is 1-49 */
#define MAX_PRIVATE_KEY 49

/* Basic ECC operations */
int mod(int x);
int mod_inverse(int a);

Point point_add(Point P1, Point P2);
Point point_double(Point P);
Point scalar_multiply(int k, Point P);

/* Key generation */
int generate_private_key(void);

Point generate_public_key(int private_key);

Point generate_shared_secret(
    int private_key,
    Point other_public_key
);

#endif