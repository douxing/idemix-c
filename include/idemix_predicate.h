#ifndef __IDEMIX_PREDICATE_H__
#define __IDEMIX_PREDICATE_H__

#include <gmp.h>

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
};
typedef struct predicate_s *predicate_ptr;
typedef struct predicate_s predicate_t[1];

void predicate_init_assign
(predicate_t p, // OUT
 enum operator op,
 mpz_t m,
 mpz_t z);

#endif // __IDEMIX_PREDICATE_H__
