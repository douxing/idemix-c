#ifndef __IDEMIX_UTILS_H__
#define __IDEMIX_UTILS_H__

#include <gmp.h>

#define REPS_VAL 15

enum operator {
  GREATER_THAN_OR_EQUAL_TO,
  EQUAL_TO,
  LESS_THAN_OR_EQUAL_TO,
};

gmp_randstate_t g_randstate;
void initialize();

void random_n_bits(mpz_t num, unsigned long bits);
void random_prime(mpz_t prime, unsigned long bits);

#endif
