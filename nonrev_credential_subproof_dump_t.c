#include "idemix_nonrev_credential_subproof_dump_t.h"
#include "idemix_pairing.h"

void nonrev_credential_subproof_dump_t
(mpz_vec_t T,
 pairing_t pairing,
 nonrev_pk_t pk,
 accumulator_t acc,
 nonrev_credential_subproof_auxiliary_t nrcspa,
 nonrev_credential_subproof_tuple_c_t C)
{
  // 1. Load Issuer's public revocation key
  // 2. Load the non-revocation credential C_NR
  // 3. Obtain recent V, acc

  // 4. Update C_NR
  // idemix_non_revocation_credentials.h
  // nonrev_credential_update(nrc, acc);

  // 5. Select random ... mod q
  // 6. Compute
  //    E, D, A, G, W, S, U in Eq. (22) ~ (25)
  //    in tuple C

  // page 7 Eq. (28) ~ (32)
  mpz_t z;
  mpz_init(z);
  element_t t, t1, t2, t3, t4, z1, z2, z3;

  // T1 bar
  element_init_G1(t, pairing);
  element_pow2_zn(t,
		  pk->h, nrcspa->rho_tilde,
		  pk->h_tilde, nrcspa->o_tilde);
  element_to_mpz(z, nrcspa->rho_tilde);
  pbc_element_to_mpz(z, t);
  mpz_vec_append(T, z);
  element_clear(t);

  // T2 bar
  element_init_G1(t, pairing);
  element_init_Zr(z1, pairing);
  element_init_Zr(z2, pairing);
  element_neg(z1, nrcspa->m_tilde);
  element_neg(z2, nrcspa->t_tilde);
  element_pow3_zn(t,
		  C->E, nrcspa->c_tilde,
		  pk->h, z1,
		  pk->h_tilde, z2);
  pbc_element_to_mpz(z, t);
  mpz_vec_append(T, z);
  element_clear(t);
  element_clear(z1);
  element_clear(z2);

  // T3 bar
  element_init_GT(t, pairing);
  element_init_GT(t1, pairing);
  element_init_GT(t2, pairing);
  element_init_GT(t3, pairing);
  element_init_Zr(z1, pairing);
  element_init_Zr(z2, pairing);
  element_init_Zr(z3, pairing);

  element_pairing(t1, C->A, pk->h_caret);
  element_pairing(t2, pk->h_tilde, pk->h_caret);
  element_pairing(t3, pk->h_tilde, pk->y);
  element_neg(z3, nrcspa->rho_tilde);
  element_pow3_zn(t,
		  t1, nrcspa->c_tilde,
		  t2, nrcspa->r_tilde,
		  t3, z3);

  element_pairing(t1, pk->h_tilde, pk->h_caret);
  element_neg(z1, nrcspa->m_tilde);
  element_pairing(t2, pk->h1, pk->h_caret);
  element_neg(z2, nrcspa->m2_tilde);
  element_pairing(t3, pk->h2, pk->h_caret);
  element_neg(z3, nrcspa->s_tilde);
  element_pow3_zn(t1, t1, z1, t2, z2, t3, z3);
  element_mul(t, t, t1);
  pbc_element_to_mpz(z, t);
  mpz_vec_append(T, z);
  element_clear(t);
  element_clear(t1);
  element_clear(t2);
  element_clear(t3);
  element_clear(z1);
  element_clear(z2);
  element_clear(z3);

  // T4 bar
  element_init_G1(t, pairing);
  element_init_GT(t1, pairing);
  element_init_GT(t2, pairing);
  element_pairing(t1, pk->h_tilde, acc->acc);
  element_invert(t, acc->g);
  element_pairing(t2, t, pk->h_caret);
  element_pow2_zn(t1,
		  t1, nrcspa->r_tilde,
		  t2, nrcspa->r_apos_tilde);
  pbc_element_to_mpz(z, t1);
  mpz_vec_append(T, z);
  element_clear(t);
  element_clear(t1);
  element_clear(t2);

  // T5 bar
  element_init_G1(t, pairing);
  element_pow2_zn(t,
		  acc->g, nrcspa->r_tilde,
		  pk->h_tilde, nrcspa->o_apos_tilde);
  pbc_element_to_mpz(z, t);
  mpz_vec_append(T, z);
  element_printf("T5 bar: %B\n", t);
  element_clear(t);

  // T6 bar
  element_init_G1(t, pairing);
  element_init_G1(t1, pairing);
  element_init_G1(t2, pairing);
  element_invert(t1, acc->g);
  element_invert(t2, pk->h_tilde);
  element_pow3_zn(t,
		  C->D, nrcspa->r_apos2_tilde,
		  t1, nrcspa->m_apos_tilde,
		  t2, nrcspa->t_apos_tilde);
  pbc_element_to_mpz(z, t);
  mpz_vec_append(T, z);
  element_clear(t);
  element_clear(t1);
  element_clear(t2);

  // T7 bar
  element_init_G1(t, pairing);
  element_init_GT(t1, pairing);
  element_init_GT(t2, pairing);
  element_init_GT(t3, pairing);
  element_init_GT(t4, pairing);
  element_mul(t, pk->pk, C->G);
  element_pairing(t1, t, pk->h_caret);
  element_pairing(t2, pk->h_tilde, pk->h_caret);
  element_invert(t2, t2);
  element_pairing(t3, pk->h_tilde, C->S);
  element_pow3_zn(t4,
		  t1, nrcspa->r_apos2_tilde,
		  t2, nrcspa->m_apos_tilde,
		  t3, nrcspa->r_tilde);
  pbc_element_to_mpz(z, t4);
  mpz_vec_append(T, z);
  element_clear(t);
  element_clear(t1);
  element_clear(t2);
  element_clear(t3);
  element_clear(t4);

  // T8 bar
  element_init_G1(t, pairing);
  element_init_GT(t1, pairing);
  element_init_GT(t2, pairing);
  element_init_GT(t3, pairing);
  element_pairing(t1, pk->h_tilde, pk->u);
  element_invert(t, acc->g);
  element_pairing(t2, t, pk->h_caret);
  element_pow2_zn(t3,
		  t1, nrcspa->r_tilde,
		  t2, nrcspa->r_apos3_tilde);
  pbc_element_to_mpz(z, t3);
  mpz_vec_append(T, z);
  element_clear(t);
  element_clear(t1);
  element_clear(t2);
  element_clear(t3);

  mpz_clear(z);
}
