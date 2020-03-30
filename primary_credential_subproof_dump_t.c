#include "idemix_primary_credential_subproof_dump_t.h"

void primary_credential_subproof_dump_t
(mpz_vec_t T,
 issuer_pk_t pk,
 attr_vec_t m_tildes, // intersection(Cs, Ar)
 primary_credential_subproof_auxiliary_t pcspa,
 primary_credential_subproof_tuple_c_t C)
{
  // Eq. (34)
  mpz_t t0, t1;
  mpz_inits(t0, t1, NULL);

  mpz_powm(t0, C->A_apos, pcspa->e_tilde, pk->n); // (A')^e~
  mpz_mod(t0, t0, pk->n);

  for (unsigned long i = 0; i < attr_vec_size(m_tildes); ++i) {
    attr_ptr ap = attr_vec_head(m_tildes) + i;
    mpz_powm(t1, pk->R_v + ap->i, ap->v, pk->n); // Rj^mj~
    mpz_mul(t0, t0, t1);
    mpz_mod(t0, t0, pk->n);
  }

  mpz_powm(t1, pk->S, pcspa->v_tilde, pk->n); // S^v~
  mpz_mul(t0, t0, t1);
  mpz_mod(t0, t0, pk->n);

  mpz_vec_append(T, t0);
  
  mpz_clears(t0, t1, NULL);
}
