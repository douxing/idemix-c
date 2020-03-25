#include "idemix_predicate.h"

void predicate_init_assign
(predicate_t p, // OUT
 enum operator op,
 mpz_t m,
 mpz_t z)
{
  // assert op in enum operator
  p->op = op;
  mpz_init_set(p->m, m);
  mpz_init_set(p->z, z);
}

void predicate_clear(predicate_t p)
{
  mpz_clears(p->m, p->z, NULL);
}
