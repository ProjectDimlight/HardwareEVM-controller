
#define RSA_KEY_LENGTH 1024
#define PRIME_TEST_ITERATIONS 20

void RSA_encrypt(mpz_t c, mpz_t m, mpz_t n, mpz_t e);
void RSA_decrypt(mpz_t m, mpz_t c, mpz_t n, mpz_t d);

void RSA_sign(mpz_t s, mpz_t m, mpz_t n, mpz_t d, mpz_t e)
int  RSA_verify(mpz_t s, mpz_t m, mpz_t n, mpz_t d, mpz_t e);