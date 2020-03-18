#include "idemix_primary_credential_subproof_tuple_c.h"

void primary_credential_subproof_tuple_c_init
(primary_credential_subproof_tuple_c_t C)
{
  mpz_inits(C->A_apos, NULL);
}

void primary_credential_subproof_tuple_c_clear(primary_credential_subproof_tuple_c_t C)
{
  mpz_clear(C->A_apos);
}

void primary_credential_subproof_tuple_c_assign
(primary_credential_subproof_tuple_c_t C,
 issuer_pk_t pk,
 primary_credential_t pc,
 primary_credential_subproof_auxiliary_t pcspa)
{
  mpz_powm(C->A_apos, pk->S, pcspa->r, pk->n);
  mpz_mul(C->A_apos, pc->A, C->A_apos);
  mpz_mod(C->A_apos, C->A_apos, pk->n); // A' = AS^r mod n
}

void primary_credential_subproof_tuple_c_into_vec
(mpz_vec_t v, // OUT
 primary_credential_subproof_tuple_c_t C)
{
  mpz_vec_append(v, C->A_apos);
}
