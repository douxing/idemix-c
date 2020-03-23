#include "idemix_nonrev_credential_subproof_tuple_c.h"

void nonrev_credential_subproof_tuple_c_init
(nonrev_credential_subproof_tuple_c_t C,
 pairing_t pairing)
{
  element_init_G1(C->E, pairing);
  element_init_G1(C->D, pairing);
  element_init_G1(C->A, pairing);
  element_init_G1(C->G, pairing);
  element_init_G2(C->W, pairing);
  element_init_G2(C->S, pairing);
  element_init_G2(C->U, pairing);
}

void nonrev_credential_subproof_tuple_c_clear
(nonrev_credential_subproof_tuple_c_t C)
{
  element_clear(C->E);
  element_clear(C->D);
  element_clear(C->A);
  element_clear(C->G);
  element_clear(C->W);
  element_clear(C->S);
  element_clear(C->U);
}

void nonrev_credential_subproof_tuple_c_assign
(nonrev_credential_subproof_tuple_c_t C,
 nonrev_pk_t pk,
 nonrev_credential_t nrc,
 nonrev_credential_subproof_auxiliary_t nrcspa,
 accumulator_t acc)
{
  // 6. Compute
  //    E, D, A, G, W, S, U in Eq. (22) ~ (25)
  element_pow2_zn(C->E, pk->h, nrcspa->rho, pk->h_tilde, nrcspa->o); // E
  element_pow2_zn(C->D, acc->g, nrcspa->r, pk->h_tilde, nrcspa->o_apos); // D
  element_pow_zn(C->A, pk->h_tilde, nrcspa->rho);
  element_mul(C->A, nrc->sigma, C->A); // A
  element_pow_zn(C->G, pk->h_tilde, nrcspa->r);
  element_mul(C->G, nrc->g_i, C->G); // G
  element_pow_zn(C->W, pk->h_caret, nrcspa->r_apos);
  element_mul(C->W, nrc->wit_i->w, C->W); // W
  element_pow_zn(C->S, pk->h_caret, nrcspa->r_apos2);
  element_mul(C->S, nrc->wit_i->sigma_i, C->S); // S
  element_pow_zn(C->U, pk->h_caret, nrcspa->r_apos3);
  element_mul(C->U, nrc->wit_i->u_i, C->U); // U
}

void nonrev_credential_subproof_tuple_c_into_vec
(mpz_vec_t v,
 nonrev_credential_subproof_tuple_c_t C)
{
  mpz_t t;
  mpz_init(t);

  element_to_mpz(t, C->E);
  mpz_vec_append(v, t);
  element_to_mpz(t, C->D);
  mpz_vec_append(v, t);
  element_to_mpz(t, C->A);
  mpz_vec_append(v, t);
  element_to_mpz(t, C->G);
  mpz_vec_append(v, t);
  element_to_mpz(t, C->W);
  mpz_vec_append(v, t);
  element_to_mpz(t, C->S);
  mpz_vec_append(v, t);
  element_to_mpz(t, C->U);
  mpz_vec_append(v, t);

  mpz_clear(t);
}
