#ifndef __IDEMIX_UTILS_H__
#define __IDEMIX_UTILS_H__

#include <gmp.h>

#define REPS_VAL 15
#define BUF_SIZE 512 // make sure it is big

enum operator {
  GREATER_THAN_OR_EQUAL_TO,
  EQUAL_TO,
  LESS_THAN_OR_EQUAL_TO,
};

void random_num();
void random_num_exact_bits(mpz_t num, unsigned long bits);
void random_range(mpz_t num, mpz_t min, mpz_t max);
void random_prime(mpz_t prime, unsigned long bits);
void random_prime_exact_bits(mpz_t prime, unsigned long bits);

#endif
