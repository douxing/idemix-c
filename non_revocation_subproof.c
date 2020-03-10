#include "idemix_non_revocation_subproof.h"

#define INIT_AND_RANDOM(e, p)			\
  do {						\
    element_init_Zr((e), (p));			\
    element_random(e);				\
  } while(0)

void nonrev_subproof_rand_init_random
(nonrev_subproof_rand_t r,
 pairing_t p)
{
  INIT_AND_RANDOM(r->rho, p);
  INIT_AND_RANDOM(r->rho_apos, p);
  INIT_AND_RANDOM(r->r, p);
  INIT_AND_RANDOM(r->r_apos, p);
  INIT_AND_RANDOM(r->r_apos2, p);
  INIT_AND_RANDOM(r->r_apos3, p);
  INIT_AND_RANDOM(r->o, p);
  INIT_AND_RANDOM(r->o_apos, p);

  INIT_AND_RANDOM(r->rho_tilde, p);
  INIT_AND_RANDOM(r->o_tilde, p);
  INIT_AND_RANDOM(r->o_apos_tilde, p);
  INIT_AND_RANDOM(r->c_tilde, p);
  INIT_AND_RANDOM(r->m_tilde, p);
  INIT_AND_RANDOM(r->m_apos_tilde, p);
  INIT_AND_RANDOM(r->t_tilde, p);
  INIT_AND_RANDOM(r->t_apos_tilde, p);
  INIT_AND_RANDOM(r->m2_tilde, p);
  INIT_AND_RANDOM(r->s_tilde, p);
  INIT_AND_RANDOM(r->r_tilde, p);
  INIT_AND_RANDOM(r->r_apos_tilde, p);
  INIT_AND_RANDOM(r->r_apos2_tilde, p);
  INIT_AND_RANDOM(r->r_apos3_tilde, p);
}

void nonrev_subproof_init
(nonrev_subproof_t nrp,
 pairing_t p)
{
  element_init_G1(nrp->E, p);
  element_init_G1(nrp->D, p);
  element_init_G1(nrp->A, p);
  element_init_G1(nrp->G, p);
  element_init_G1(nrp->W, p);
  element_init_G1(nrp->S, p);
  element_init_G1(nrp->U, p);

  element_init_Zr(nrp->m, p);
  element_init_Zr(nrp->t, p);
  element_init_Zr(nrp->m_apos, p);
  element_init_Zr(nrp->t_apos, p);

  element_init_G1(nrp->T1_bar, p);
  element_init_G1(nrp->T2_bar, p);
  element_init_G1(nrp->T3_bar, p);
  element_init_G1(nrp->T4_bar, p);
  element_init_G1(nrp->T5_bar, p);
  element_init_G1(nrp->T6_bar, p);
  element_init_G1(nrp->T7_bar, p);
  element_init_G1(nrp->T8_bar, p);
}

void nonrev_subproof_assign
(nonrev_subproof_t nrsp, // OUT
 nonrev_credential_t nrc,  // OUT
 nonrev_pk_t pk,
 accumulator_t acc,
 nonrev_subproof_rand_t r)
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
  element_pow2_zn(nrsp->E, pk->h, r->rho, pk->h_tilde, r->o); // E
  element_pow2_zn(nrsp->D, acc->g, r->r, pk->h_tilde, r->o_apos); // D
  element_pow_zn(nrsp->A, pk->h_tilde, r->rho);
  element_mul(nrsp->A, nrc->sigma, nrsp->A); // A
  element_pow_zn(nrsp->G, pk->h_tilde, r->r);
  element_mul(nrsp->G, nrc->g_i, nrsp->G); // G
  element_pow_zn(nrsp->W, pk->h_caret, r->r_apos);
  element_mul(nrsp->W, nrc->wit_i->w, nrsp->W); // W
  element_pow_zn(nrsp->S, pk->h_caret, r->r_apos2);
  element_mul(nrsp->S, nrc->wit_i->sigma_i, nrsp->S); // S
  element_pow_zn(nrsp->U, pk->h_caret, r->r_apos3);
  element_mul(nrsp->U, nrc->wit_i->u_i, nrsp->U); // U
  
  // page 7 Eq. (26) (27)
  element_mul(nrsp->m, r->rho, nrc->c);
  element_mul(nrsp->t, r->o, nrc->c);
  element_mul(nrsp->m_apos, r->r, r->r_apos2);
  element_mul(nrsp->t_apos, r->o_apos, r->r_apos2);

  // page 7 Eq. (28) ~ (32)
  element_t t, t1, t2, t3;

  // T1 bar
  element_pow2_zn(nrsp->T1_bar,
		  pk->h, r->rho_tilde,
		  pk->h_tilde, r->o_tilde);

  // T2 bar
  element_init_same_as(t1, nrsp->T2_bar);
  element_init_same_as(t2, nrsp->T2_bar);
  element_invert(t1, pk->h);
  element_invert(t2, pk->h_tilde);
  element_pow3_zn(nrsp->T2_bar,
		  nrsp->E, r->c_tilde,
		  t1, r->m_tilde,
		  t2, r->t_tilde);
  element_clear(t1);
  element_clear(t2);

  // T3 bar
  element_init_same_as(t, nrsp->T3_bar);
  element_init_same_as(t1, nrsp->T3_bar);
  element_init_same_as(t2, nrsp->T3_bar);
  element_init_same_as(t3, nrsp->T3_bar);
  element_pairing(t1, nrsp->A, pk->h_caret);
  element_pairing(t2, pk->h_tilde, pk->h_caret);
  element_pairing(t3, pk->h_tilde, pk->y);
  element_invert(t3, t3);
  element_pow3_zn(nrsp->T3_bar,
		  t1, r->c_tilde,
		  t2, r->r_tilde,
		  t3, r->rho_tilde);
  element_pairing(t1, pk->h_tilde, pk->h_caret);
  element_invert(t1, t1);
  element_pairing(t2, pk->h1, pk->h_caret);
  element_invert(t2, t2);
  element_pairing(t3, pk->h2, pk->h_caret);
  element_invert(t3, t3);
  element_pow3_zn(t, t1, r->m_tilde, t2, r->m2_tilde, t3, r->s_tilde);
  element_mul(nrsp->T3_bar, nrsp->T3_bar, t);
  element_clear(t);
  element_clear(t1);
  element_clear(t2);
  element_clear(t3);

  // T4 bar
  element_init_same_as(t, acc->g);
  element_init_same_as(t1, nrsp->T4_bar);
  element_init_same_as(t2, nrsp->T4_bar);
  element_pairing(t1, pk->h_tilde, acc->acc);
  element_invert(t, t);
  element_pairing(t2, t, pk->h_caret);
  element_pow2_zn(nrsp->T4_bar,
		  t1, r->r_tilde,
		  t2, r->r_apos_tilde);
  element_clear(t);
  element_clear(t1);
  element_clear(t2);  

  // T5 bar
  element_pow2_zn(nrsp->T5_bar,
		  acc->g, r->r_tilde,
		  pk->h_tilde, r->o_apos_tilde);

  // T6 bar
  element_init_same_as(t1, nrsp->T6_bar);
  element_init_same_as(t2, nrsp->T6_bar);
  element_invert(t1, acc->g);
  element_invert(t2, pk->h_tilde);
  element_pow3_zn(nrsp->T6_bar,
		  nrsp->D, r->r_apos2,
		  t1, r->m_apos_tilde,
		  t2, r->t_apos_tilde);
  element_clear(t1);
  element_clear(t2);

  // T7 bar
  element_init_same_as(t, pk->pk);
  element_init_same_as(t1, nrsp->T7_bar);
  element_init_same_as(t2, nrsp->T7_bar);
  element_init_same_as(t3, nrsp->T7_bar);
  element_mul(t, pk->pk, nrsp->G);
  element_pairing(t1, t, pk->h_caret);
  element_pairing(t2, pk->h_tilde, pk->h_caret);
  element_invert(t2, t2);
  element_pairing(t3, pk->h_tilde, nrsp->S);
  element_pow3_zn(nrsp->T7_bar,
		  t1, r->r_apos2_tilde,
		  t2, r->m_apos_tilde,
		  t3, r->r_tilde);
  element_clear(t);
  element_clear(t1);
  element_clear(t2);
  element_clear(t3);

  // T8 bar
  element_init_same_as(t, acc->g);
  element_init_same_as(t1, nrsp->T8_bar);
  element_init_same_as(t2, nrsp->T8_bar);
  element_pairing(t1, pk->h_tilde, pk->u);
  element_invert(t, acc->g);
  element_pairing(t2, t, pk->h_caret);
  element_pow2_zn(nrsp->T8_bar,
		  t1, r->r_tilde,
		  t2, r->r_apos3_tilde);
}

void nonrev_subproof_into_CT
(mpz_vec_t C, // OUT
 mpz_vec_t T, // OUT
 nonrev_subproof_t nrsp)
{
  mpz_t t;
  mpz_init(t);

  // into C
  element_to_mpz(t, nrsp->E);
  mpz_vec_append(C, t);
  element_to_mpz(t, nrsp->D);
  mpz_vec_append(C, t);
  element_to_mpz(t, nrsp->A);
  mpz_vec_append(C, t);
  element_to_mpz(t, nrsp->G);
  mpz_vec_append(C, t);
  element_to_mpz(t, nrsp->W);
  mpz_vec_append(C, t);
  element_to_mpz(t, nrsp->S);
  mpz_vec_append(C, t);
  element_to_mpz(t, nrsp->U);
  mpz_vec_append(C, t);

  // into T
  element_to_mpz(t, nrsp->T1_bar);
  mpz_vec_append(T, t);
  element_to_mpz(t, nrsp->T2_bar);
  mpz_vec_append(T, t);
  element_to_mpz(t, nrsp->T3_bar);
  mpz_vec_append(T, t);
  element_to_mpz(t, nrsp->T4_bar);
  mpz_vec_append(T, t);
  element_to_mpz(t, nrsp->T5_bar);
  mpz_vec_append(T, t);
  element_to_mpz(t, nrsp->T6_bar);
  mpz_vec_append(T, t);
  element_to_mpz(t, nrsp->T7_bar);
  mpz_vec_append(T, t);
  element_to_mpz(t, nrsp->T8_bar);
  mpz_vec_append(T, t);

  mpz_clear(t);
}
