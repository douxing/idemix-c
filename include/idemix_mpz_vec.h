#ifndef __IDEMIX_MPZ_VEC_H__
#define __IDEMIX_MPZ_VEC_H__

#include <gmp.h>

#define MPZ_VEC_INITIAL_CAPACITY 32

struct mpz_vec_s {
  unsigned long next; // highest index + 1, initially 0
  unsigned long cap;  // = length of v
  mpz_ptr v;          // contains an array of mpz_t
};
typedef struct mpz_vec_s *mpz_vec_ptr;
typedef struct mpz_vec_s mpz_vec_t[1];

void mpz_vec_init(mpz_vec_t v);
void mpz_vec_clear(mpz_vec_t v);

void mpz_vec_append(mpz_vec_t v, const mpz_t val);

mpz_ptr mpz_vec_head(mpz_vec_t v);
unsigned long mpz_vec_size(mpz_vec_t v);

#endif // __IDEMIX_MPZ_VEC_H__
