#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>
#include "ecc.h"

/*
 * Elliptic Curve:
 *
 * y^2 = x^3 + 2x + 3 (mod 97)
 *
 * Generator point:
 * G = (0,10)
 *
 * The generator has order 50.
 */

/* Generator point */
static Point G = {0, 10, 0};


/* =========================================================
   Positive modulo
   ========================================================= */

int mod(int x)
{
    int r = x % PRIME;

    if (r < 0)
        r += PRIME;

    return r;
}

/* =========================================================
   Modular inverse
   ========================================================= */

int mod_inverse(int a)
{
    a = mod(a);

    if (a == 0)
        return -1;

    for (int i = 1; i < PRIME; i++)
    {
        if ((a * i) % PRIME == 1)
            return i;
    }

    return -1;
}

/* =========================================================
   Point Addition
   ========================================================= */

Point point_add(Point P1, Point P2)
{
    Point R;

    /* P1 + O = P1 */
    if (P1.infinity)
        return P2;

    /* O + P2 = P2 */
    if (P2.infinity)
        return P1;


    /*
     * P + (-P) = O
     */
    if (P1.x == P2.x &&
        mod(P1.y + P2.y) == 0)
    {
        R.x = 0;
        R.y = 0;
        R.infinity = 1;

        return R;
    }


    int lambda;


    /* Point doubling */
    if (P1.x == P2.x &&
        P1.y == P2.y)
    {
        int denominator;
        int numerator;

        numerator =
            mod(3 * P1.x * P1.x + A);

        denominator =
            mod_inverse(2 * P1.y);

        if (denominator == -1)
        {
            R.x = 0;
            R.y = 0;
            R.infinity = 1;

            return R;
        }

        lambda =
            mod(numerator * denominator);
    }
    else
    {
        /* Normal point addition */

        int numerator;
        int denominator;

        numerator =
            mod(P2.y - P1.y);

        denominator =
            mod_inverse(P2.x - P1.x);

        if (denominator == -1)
        {
            R.x = 0;
            R.y = 0;
            R.infinity = 1;

            return R;
        }

        lambda =
            mod(numerator * denominator);
    }
    /* Calculate X coordinate */
    R.x =
        mod(lambda * lambda - P1.x - P2.x);
    /* Calculate Y coordinate */
    R.y =
        mod(lambda * (P1.x - R.x) - P1.y);


    R.infinity = 0;

    return R;
}


/* =========================================================
   Point Doubling
   ========================================================= */

Point point_double(Point P)
{
    return point_add(P, P);
}


/* =========================================================
   Scalar Multiplication
   ========================================================= */

Point scalar_multiply(int k, Point P)
{
    Point result;

    result.x = 0;
    result.y = 0;
    result.infinity = 1;

    Point temp = P;


    while (k > 0)
    {
        if (k & 1)
        {
            result =
                point_add(result, temp);
        }
        temp =
            point_double(temp);

        k >>= 1;
    }


    return result;
}


/* =========================================================
   Generate Private Key
   ========================================================= */

int generate_private_key(void)
{
    static int initialized = 0;

    if (!initialized)
    {

        unsigned int seed;

        seed =
            (unsigned int)time(NULL)
            ^
            (unsigned int)GetCurrentProcessId();

        srand(seed);

        initialized = 1;
    }

    return (rand() % MAX_PRIVATE_KEY) + 1;
}


/* =========================================================
   Generate Public Key
   =========================================================

   Public Key = Private Key × G
   ========================================================= */

Point generate_public_key(int private_key)
{
    return scalar_multiply(private_key, G);
}


/* =========================================================
   Generate Shared Secret
   =========================================================

   Client:

       ClientPrivate × ServerPublic

   Server:

       ServerPrivate × ClientPublic

   Both produce the same point.
   ========================================================= */

Point generate_shared_secret(
    int private_key,
    Point other_public_key)
{
    return scalar_multiply(
        private_key,
        other_public_key);
}