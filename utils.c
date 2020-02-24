#include "idemix_utils.h"
#include <pbc/pbc.h> // gmp.h included

void random_num_bits(mpz_t num, unsigned long bits)
{
  pbc_mpz_randomb(num, bits);
}

void random_num_exact_bits(mpz_t num, unsigned long bits)
{
  pbc_mpz_randomb(num, bits - 1);
  mpz_setbit(num, bits - 1);
}

// output a random number in [min, max - 1]
void random_range(mpz_t num, mpz_t min, mpz_t max)
{
  mpz_sub(num, max, min);
  pbc_mpz_random(num, num);
  mpz_add(num, num, min);
}

// output a prime of n bits
void random_prime_bits(mpz_t prime, unsigned long bits)
{
  do {
    pbc_mpz_randomb(prime, bits);
  } while(mpz_probab_prime_p(prime, REPS_VAL));
}

void random_prime_exact_bits(mpz_t num, unsigned long bits)
{
  do {
    random_exact_bits(prime, bits);
  } while(mpz_probab_prime_p(prime, REPS_VAL));
}
