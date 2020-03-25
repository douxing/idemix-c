#include "idemix_nonrev_credential_subcheck_dump_t.h"
#include "idemix_pairing.h"

void nonrev_credential_subcheck_dump_t
(mpz_vec_t T,
 pairing_t pairing,
 mpz_t CH,
 accumulator_t acc,
 accumulator_pk_t accpk,
 nonrev_pk_t pk,
 tuple_x_t X, // de facto nonrev_credential_subproof_t
 nonrev_credential_subproof_tuple_c_t C)
{
  mpz_t z;
  mpz_init(z);
  element_t eCH, t, t1, t2, t3, t4, z1, z2, z3;
  element_init_Zr(eCH, pairing);
  element_set_mpz(eCH, CH);
  gmp_printf("CH: %Zd\n", CH);

  // T1^
  element_init_G1(t, pairing);
  element_pow3_zn(t,
		  C->E, eCH,
		  pk->h, X->rho_caret,
		  pk->h_tilde, X->o_caret);
  element_to_mpz(z, X->rho_caret);
  pbc_element_to_mpz(z, t);
  mpz_vec_append(T, z);
  element_clear(t);

  // T2^
  element_init_G1(t, pairing);
  element_init_Zr(z1, pairing);
  element_init_Zr(z2, pairing);
  element_neg(z1, X->m_caret);
  element_neg(z2, X->t_caret);
  element_pow3_zn(t,
		  C->E, X->c_caret,
		  pk->h, z1,
		  pk->h_tilde, z2);
  pbc_element_to_mpz(z, t);
  mpz_vec_append(T, z);
  element_clear(t);
  element_clear(z1);
  element_clear(z2);

  // T3^
  element_init_G1(t, pairing);
  element_init_GT(t1, pairing);
  element_init_GT(t2, pairing);
  element_init_GT(t3, pairing);
  element_init_GT(t4, pairing);
  element_init_Zr(z1, pairing);
  element_init_Zr(z2, pairing);
  element_init_Zr(z3, pairing);

  element_mul(t, pk->h0, C->G);
  element_pairing(t1, t, pk->h_caret);
  element_pairing(t2, C->A, pk->y);
  element_neg(z2, eCH); // z2 = -CH
  element_pairing(t3, C->A, pk->h_caret);
  element_pow3_zn(t4, t1, eCH, t2, z2, t3, X->c_caret);

  element_pairing(t1, pk->h_tilde, pk->h_caret);
  element_sub(z1, X->r_caret, X->m_caret);
  element_pairing(t2, pk->h_tilde, pk->y);
  element_neg(z2, X->rho_caret);
  element_pairing(t3, pk->h1, pk->h_caret);
  element_neg(z3, X->m2_caret);
  element_pow3_zn(t1, t1, z1, t2, z2, t3, z3);
  element_mul(t4, t4, t1);

  element_pairing(t1, pk->h2, pk->h_caret);
  element_neg(z1, X->s_caret);
  element_pow_zn(t1, t1, z1);
  element_mul(t4, t4, t1);

  pbc_element_to_mpz(z, t4);
  mpz_vec_append(T, z);
  element_clear(t);
  element_clear(t1);
  element_clear(t2);
  element_clear(t3);
  element_clear(t4);
  element_clear(z1);
  element_clear(z2);
  element_clear(z3);


  // T4^
  element_init_G1(t, pairing);
  element_init_GT(t1, pairing);
  element_init_GT(t2, pairing);
  element_init_GT(t3, pairing);
  element_init_Zr(z1, pairing);
  element_pairing(t1, C->G, acc->acc);
  element_pairing(t2, acc->g, C->W);
  element_neg(z1, eCH);
  element_pow3_zn(t3, t1, eCH, t2, z1, accpk->z, z1);
  
  element_invert(t, acc->g);
  element_pairing(t1, pk->h_tilde, acc->acc);
  element_pairing(t2, t, pk->h_caret);
  element_pow2_zn(t1, t1, X->r_caret, t2, X->r_apos_caret);
  element_mul(t1, t3, t1);
  element_printf("T4 car: %B\n", t1);

  pbc_element_to_mpz(z, t1);
  mpz_vec_append(T, z);
  element_clear(t);
  element_clear(t1);
  element_clear(t2);
  element_clear(t3);

  // T5^
  element_init_G1(t, pairing);
  element_pow3_zn(t,
		  C->D, eCH,
		  acc->g, X->r_caret,
		  pk->h_tilde, X->o_apos_caret);
  pbc_element_to_mpz(z, t);
  mpz_vec_append(T, z);
  element_clear(t);

  // T6^
  element_init_G1(t1, pairing);
  element_init_G1(t2, pairing);
  element_invert(t1, acc->g);
  element_invert(t2, pk->h_tilde);
  element_pow3_zn(t1,
		  C->D, X->r_apos2_caret,
		  t1, X->m_apos_caret,
		  t2, X->t_apos_caret);
  pbc_element_to_mpz(z, t1);
  mpz_vec_append(T, z);
  element_clear(t1);
  element_clear(t2);

  // T7^
  element_init_G1(t, pairing);
  element_init_GT(t1, pairing);
  element_init_GT(t2, pairing);
  element_init_GT(t3, pairing);
  element_mul(t, pk->pk, C->G);
  element_pairing(t1, t, C->S);
  element_pairing(t2, acc->g, acc->g_apos);
  element_div(t1, t1, t2);
  element_pairing(t2, t, pk->h_caret);
  element_pairing(t3, pk->h_tilde, pk->h_caret);
  element_invert(t3, t3);
  element_pow3_zn(t1,
		  t1, eCH,
		  t2, X->r_apos2_caret,
		  t3, X->m_apos_caret);
  element_pairing(t2, pk->h_tilde, C->S);
  element_pow_zn(t2, t2, X->r_caret);
  element_mul(t1, t1, t2);
  pbc_element_to_mpz(z, t1);
  mpz_vec_append(T, z);
  element_clear(t);
  element_clear(t1);
  element_clear(t2);
  element_clear(t3);

  // T8^
  element_init_G1(t, pairing);
  element_init_GT(t1, pairing);
  element_init_GT(t2, pairing);
  element_init_GT(t3, pairing);
  element_pairing(t1, C->G, pk->u);
  element_pairing(t2, acc->g, C->U);
  element_div(t1, t1, t2);
  element_pairing(t2, pk->h_tilde, pk->u);
  element_invert(t, acc->g);
  element_pairing(t3, t, pk->h_caret);
  element_pow3_zn(t1,
		  t1, eCH,
		  t2, X->r_caret,
		  t3, X->r_apos3_caret);
  pbc_element_to_mpz(z, t1);
  mpz_vec_append(T, z);
  element_clear(t);
  element_clear(t1);
  element_clear(t2);
  element_clear(t3);

  mpz_clear(z);
}
