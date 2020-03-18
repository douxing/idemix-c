#include "idemix_primary_credential_subcheck_t.h"

// Eq. (54)
void primary_credential_subcheck_t_into_vec
(mpz_vec_t T,
 issuer_pk_t pk,
 mpz_t CH,
 attr_vec_t v, // revealed attributes
 primary_credential_subproof_t pcsp)
{
  // assert(pk->R_c == attr_vec_size(v) + attr_vec_size(pcsp->m_carets));

  mpz_t t, t1, t2;
  mpz_inits(t, t1, t2, NULL);
  
  mpz_set_ui(t1, 1);
  for (unsigned long i = 0; i < attr_vec_size(v); ++i) {
    // revealed member
    attr_ptr ap = attr_vec_head(v) + i;
    mpz_powm(t, pk->R_v[ap->i], ap->v, pk->n);
    mpz_mul(t1, t1, t);
    mpz_mod(t1, t1, pk->n);
  }

  // h == Rj^mj, j = intersection(Cs, Ar_bar)
  // r == Rj^mj, j = intersection(Cs, Ar)
  mpz_set_ui(t, 0);
  mpz_setbit(t, 596);
  mpz_powm(t, pcsp->A_apos, t, pk->n);
  mpz_mul(t1, t1, t);
  mpz_mod(t1, t1, pk->n);
  mpz_invert(t2, pk->Z, pk->n);
  mpz_mul(t1, t1, t2);
  mpz_mod(t1, t1, pk->n);
  mpz_powm(t1, t1, CH, pk->n);
  
  mpz_powm(t2, pcsp->A_apos, pcsp->e_caret, pk->n);
  mpz_mul(t1, t1, t2);
  mpz_mod(t1, t1, pk->n);

  mpz_set_ui(t2, 1);
  for (unsigned long i = 0; i < attr_vec_size(pcsp->m_carets); ++i) {
    // hidden member
    attr_ptr ap = attr_vec_head(pcsp->m_carets) + i;
    mpz_powm(t, pk->R_v[ap->i], ap->v, pk->n);
    mpz_mul(t2, t2, t);
    mpz_mod(t2, t2, pk->n);
  }
  mpz_mul(t1, t1, t2);
  mpz_mod(t1, t1, pk->n);

  mpz_powm(t2, pk->S, pcsp->v_caret, pk->n);
  mpz_mul(t1, t1, t2);
  mpz_mod(t1, t1, pk->n);

  mpz_vec_append(T, t1);

  mpz_clears(t, t1, t2, NULL);
}

