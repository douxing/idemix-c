#include "idemix_utils.h"

#include <gmp.h>

gmp_randstate_t g_randstate;

void initialize() {
  gmp_randinit_default(g_randstate);
}

// output a random number in [0, q - 1]
void random_mod_q(mpz_t num, mpz_t q)
{
  mpz_urandomm(num, g_randstate, q);
}

// output a random number in [min, max - 1]
void random_range(mpz_t num, mpz_t min, mpz_t max)
{
  mpz_sub(num, max, min);
  random_mod_q(num, num);
  mpz_add(num, num, min);
}

// output a random number in [0, 2^bits - 1]
void random_n_bits(mpz_t num, unsigned long bits)
{
  mpz_urandomb(num, g_randstate, bits - 1);
  mpz_setbit(num, bits - 1);
}

// output a prime of n bits
void random_prime(mpz_t prime, unsigned long bits)
{
  do {
    random_n_bits(prime, bits);
  } while(mpz_probab_prime_p(prime, REPS_VAL));
}
