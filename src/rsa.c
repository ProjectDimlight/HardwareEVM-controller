#include <gmp.h>
#include "rsa.h"

#define RSA_KEY_LENGTH 1024
#define PRIME_TEST_ITERATIONS 20

/*
void generate_keys(mpz_t n, mpz_t e, mpz_t d) {
    mpz_t p, q, phi, gcd, tmp;
    gmp_randstate_t state;
    gmp_randinit_mt(state);

    mpz_init(p);
    mpz_init(q);
    mpz_init(phi);
    mpz_init(gcd);
    mpz_init(tmp);

    // Generate two random prime numbers
    do {
        mpz_urandomb(p, state, RSA_KEY_LENGTH / 2);
        mpz_nextprime(p, p);
    } while (mpz_sizeinbase(p, 2) != RSA_KEY_LENGTH / 2);

    do {
        mpz_urandomb(q, state, RSA_KEY_LENGTH / 2);
        mpz_nextprime(q, q);
    } while (mpz_sizeinbase(q, 2) != RSA_KEY_LENGTH / 2);

    // Calculate n = p * q
    mpz_mul(n, p, q);

    // Calculate phi = (p - 1) * (q - 1)
    mpz_sub_ui(tmp, p, 1);
    mpz_sub_ui(phi, q, 1);
    mpz_mul(phi, phi, tmp);

    // Choose e such that 1 < e < phi and gcd(e, phi) = 1
    do {
        mpz_urandomm(e, state, phi);
        mpz_gcd(gcd, e, phi);
    } while (mpz_cmp_ui(gcd, 1) != 0);

    // Calculate d such that d * e = 1 (mod phi)
    mpz_invert(d, e, phi);

    // Clean up
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(phi);
    mpz_clear(gcd);
    mpz_clear(tmp);
    gmp_randclear(state);
}
*/

void encrypt(mpz_t c, mpz_t m, mpz_t n, mpz_t e) {
    mpz_powm(c, m, e, n);
}

void decrypt(mpz_t m, mpz_t c, mpz_t n, mpz_t d) {
    mpz_powm(m, c, d, n);
}

void sign(mpz_t s, mpz_t m, mpz_t n, mpz_t d, mpz_t e) {
    mpz_t salt, padded, tmp;
    gmp_randstate_t state;
    gmp_randinit_mt(state);

    mpz_init(salt);
    mpz_init(padded);
    mpz_init(tmp);

    // Generate random salt value
    mpz_urandomb(salt, state, RSA_KEY_LENGTH / 8);

    // Apply PSS padding scheme
    mpz_powm(padded, salt, d, n);
    mpz_mul(padded, padded, m);
    mpz_powm(tmp, salt, d, n);
    mpz_mod(tmp, tmp, n);
    mpz_sub_ui(tmp, tmp, 1);
    mpz_mul(tmp, tmp, e);
    mpz_invert(tmp, tmp, n);
    mpz_mul(padded, padded, tmp);
    mpz_mod(padded, padded, n);

    // Set signature
    mpz_set(s, padded);

    // Clean up
    mpz_clear(salt);
    mpz_clear(padded);
    mpz_clear(tmp);
    gmp_randclear(state);
}

int verify(mpz_t s, mpz_t m, mpz_t n, mpz_t d, mpz_t e) {
    mpz_t padded, salt, tmp;
    gmp_randstate_t state;
    gmp_randinit_mt(state);

    mpz_init(padded);
    mpz_init(salt);
    mpz_init(tmp);

    // Verify PSS padding scheme
    mpz_powm(padded, s, e, n);
    mpz_mod(tmp, padded, n);
    mpz_powm(tmp, tmp, d, n);
    mpz_sub_ui(tmp, tmp, 1);
    mpz_mul(tmp, tmp, e);
    mpz_invert(tmp, tmp, n);
    mpz_mul(tmp, tmp, padded);
    mpz_mod(tmp, tmp, n);
    mpz_tdiv_q_2exp(salt, tmp, RSA_KEY_LENGTH);
    mpz_tdiv_r_2exp(m, tmp, RSA_KEY_LENGTH);

    // Check if message matches
    int match = mpz_cmp(m, original_message) == 0;

    // Clean up
    mpz_clear(padded);
    mpz_clear(salt);
    mpz_clear(tmp);
    gmp_randclear(state);

    return match;
}