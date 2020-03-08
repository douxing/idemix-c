#ifndef __IDEMIX_PREDICATE_H__
#define __IDEMIX_PREDICATE_H__

#include <gmp.h>
#include "idemix_utils.h"

enum operator {
  LESS_THAN_OR_EQUAL_TO,
  LESS_THAN,
  GREATER_THAN_OR_EQUAL_TO,
  GREATER_THAN,
};

struct predicate_s {
  enum operator op;
  mpz_t m;
  mpz_t z;

  mpz_t delta; // determined by op
  mpz_t u1;
  mpz_t u2;
  mpz_t u3;
  mpz_t u4;

  mpz_t r_delta;
  mpz_t r1;
  mpz_t r2;
  mpz_t r3;
  mpz_t r4;

  mpz_t u1_tilde;
  mpz_t u2_tilde;
  mpz_t u3_tilde;
  mpz_t u4_tilde;

  mpz_t r_delta_tilde;
  mpz_t r1_tilde;
  mpz_t r2_tilde;
  mpz_t r3_tilde;
  mpz_t r4_tilde;

  mpz_t alpha_tilde;
};
typedef struct predicate_s *predicate_ptr;
typedef struct predicate_s predicate_t[1];

void predicate_init_with_params
(predicate_t p, // OUT
 enum operator op,
 mpz_t m,
 mpz_t z);


#endif // __IDEMIX_PREDICATE_H__
