#include "idemix_predicate_subcheck_t.h"

// Eq. (55) (56) (57)
void predicate_subcheck_t_into_vec
(mpz_vec_t T,
 issuer_pk_t pk,
 mpz_t CH,
 predicate_t p,
 predicate_subproof_tuple_c_t C,
 predicate_subproof_t psp)
{
  mpz_t t, t1;
  mpz_inits(t, t1);

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
  mpz_powm(t, pk->Z, p->z, pk->n);
  mpz_mul(t, C->T_delta, t);
  mpz_mod(t, t, pk->n);
  mpz_invert(t, t, pk->n);
  mpz_powm(t, t, CH, pk->n);
  mpz_powm(t1, pk->Z, psp->m_caret, pk->n);
  mpz_mul(t, t, t1);
  mpz_mod(t, t, pk->n);
  mpz_powm(t1, pk->S, psp->r_delta_caret, pk->n);
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

  mpz_clears(t, t1);
}

