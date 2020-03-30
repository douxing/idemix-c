#include "idemix_predicate_subcheck_dump_t.h"
#include <assert.h>

// Eq. (55) (56) (57)
void predicate_subcheck_dump_t
(mpz_vec_t T,
 issuer_pk_t pk,
 mpz_t CH,
 predicate_t p,
 predicate_subproof_tuple_c_t C,
 predicate_subproof_t psp)
{
  mpz_t t, t1, delta;
  mpz_inits(t, t1, delta, NULL);

  for (unsigned long i = 0; i < 4; ++i) { // Eq. (55)
    mpz_invert(t, C->T[i], pk->n);
    mpz_powm(t, t, CH, pk->n);
    mpz_powm(t1, pk->Z, psp->u_caret[i], pk->n);
    mpz_mul(t, t, t1);
    mpz_mod(t, t, pk->n);
    mpz_powm(t1, pk->S, psp->r_caret[i], pk->n);
    mpz_mul(t, t, t1);
    mpz_mod(t, t, pk->n);

    mpz_vec_append(T, t); // append T[i]^
  }

  // Eq. (56)
  switch (p->op) {
  case LESS_THAN_OR_EQUAL_TO:
  case GREATER_THAN_OR_EQUAL_TO:
    mpz_set(delta, p->z);
    break;
  case LESS_THAN:
    mpz_sub_ui(delta, p->z, 1);
    break;
  case GREATER_THAN:
    mpz_add_ui(delta, p->z, 1);
    break; 
  default:
    printf("unknown operation: %d\n", p->op);
    assert(0);
    break;
  }

  if (p->op == LESS_THAN_OR_EQUAL_TO || p->op == LESS_THAN) {
    mpz_powm(t, C->T_delta, CH, pk->n);
  } else {
    mpz_neg(t1, CH);
    mpz_powm(t, C->T_delta, t1, pk->n);
  }
  mpz_mul(t1, delta, CH);
  mpz_sub(t1, psp->m_caret, t1);
  mpz_powm(t1, pk->Z, t1, pk->n);
  mpz_mul(t, t, t1);
  mpz_mod(t, t, pk->n);
  if (p->op == LESS_THAN_OR_EQUAL_TO || p->op == LESS_THAN) {
    mpz_neg(t1, psp->r_delta_caret);
    mpz_powm(t1, pk->S, t1, pk->n);
  } else {
    mpz_powm(t1, pk->S, psp->r_delta_caret, pk->n);
  }
  mpz_mul(t, t, t1);
  mpz_mod(t, t, pk->n);
  mpz_vec_append(T, t); // append T_delta_caret

  // Eq. (57)
  mpz_invert(t, C->T_delta, pk->n);
  mpz_powm(t, t, CH, pk->n);
  for (unsigned long i = 0; i < 4; ++i) {
    mpz_powm(t1, C->T[i], psp->u_caret[i], pk->n);
    mpz_mul(t, t, t1);
    mpz_mod(t, t, pk->n);
  }
  mpz_powm(t1, pk->S, psp->alpha_caret, pk->n);
  mpz_mul(t, t, t1);
  mpz_mod(t, t, pk->n);
  mpz_vec_append(T, t); // append Q

  mpz_clears(t, t1, delta, NULL);
}
