#ifndef __IDEMIX_RANDOM_H__
#define __IDEMIX_RANDOM_H__

#include <pbc/pbc.h>
#include "idemix_parameters.h"

void random_num_bits(mpz_t num, unsigned long bits);
void random_num_exact_bits(mpz_t num, unsigned long bits);

void random_range(mpz_t num, mpz_t min, mpz_t max);
void random_prime_range(mpz_t num, mpz_t min, mpz_t max);

void random_prime_bits(mpz_t prime, unsigned long bits);
void random_prime_exact_bits(mpz_t prime, unsigned long bits);

void sm3_mpzs(mpz_ptr dest, mpz_ptr n, ...);

#endif // __IDEMIX_RANDOM_H__
