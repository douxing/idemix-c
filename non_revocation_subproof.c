#include "idemix_non_revocation_subproof.h"

void nonrev_subproof_prepare_init
(nonrev_subproof_prepare_t nrsp_prep,
 pairing_t pairing)
{
  element_init_Zr(nrsp_prep->rho, pairing);
  element_init_Zr(nrsp_prep->rho_apos, pairing);
  element_init_Zr(nrsp_prep->r, pairing);
  element_init_Zr(nrsp_prep->r_apos, pairing);
  element_init_Zr(nrsp_prep->r_apos2, pairing);
  element_init_Zr(nrsp_prep->r_apos3, pairing);
  element_init_Zr(nrsp_prep->o, pairing);
  element_init_Zr(nrsp_prep->o_apos, pairing);

  element_init_Zr(nrsp_prep->rho_tilde, pairing);
  element_init_Zr(nrsp_prep->o_tilde, pairing);
  element_init_Zr(nrsp_prep->o_apos_tilde, pairing);
  element_init_Zr(nrsp_prep->c_tilde, pairing);
  element_init_Zr(nrsp_prep->m_tilde, pairing);
  element_init_Zr(nrsp_prep->m_apos_tilde, pairing);
  element_init_Zr(nrsp_prep->t_tilde, pairing);
  element_init_Zr(nrsp_prep->t_apos_tilde, pairing);
  element_init_Zr(nrsp_prep->m2_tilde, pairing);
  element_init_Zr(nrsp_prep->s_tilde, pairing);
  element_init_Zr(nrsp_prep->r_tilde, pairing);
  element_init_Zr(nrsp_prep->r_apos_tilde, pairing);
  element_init_Zr(nrsp_prep->r_apos2_tilde, pairing);
  element_init_Zr(nrsp_prep->r_apos3_tilde, pairing);

  element_init_G1(nrsp_prep->E, pairing);
  element_init_G1(nrsp_prep->D, pairing);
  element_init_G1(nrsp_prep->A, pairing);
  element_init_G1(nrsp_prep->G, pairing);
  element_init_G1(nrsp_prep->W, pairing);
  element_init_G1(nrsp_prep->S, pairing);
  element_init_G1(nrsp_prep->U, pairing);

  element_init_Zr(nrsp_prep->m, pairing);
  element_init_Zr(nrsp_prep->t, pairing);
  element_init_Zr(nrsp_prep->m_apos, pairing);
  element_init_Zr(nrsp_prep->t_apos, pairing);

  // 1,2,5,6 in G1
  element_init_G1(nrsp_prep->T_bar[0], pairing);
  element_init_G1(nrsp_prep->T_bar[1], pairing);
  element_init_G1(nrsp_prep->T_bar[4], pairing);
  element_init_G1(nrsp_prep->T_bar[5], pairing);

  // 3,4,7,8 in GT
  element_init_GT(nrsp_prep->T_bar[2], pairing);
  element_init_GT(nrsp_prep->T_bar[3], pairing);
  element_init_GT(nrsp_prep->T_bar[6], pairing);
  element_init_GT(nrsp_prep->T_bar[7], pairing);
}

void nonrev_subproof_prepare_assign
(nonrev_subproof_prepare_t nrsp_prep,
 nonrev_pk_t pk,
 nonrev_credential_t nrc,
 accumulator_t acc)
{
  // 1. Load Issuer's public revocation key
  // 2. Load the non-revocation credential C_NR
  // 3. Obtain recent V, acc

  // 4. Update C_NR
  // idemix_non_revocation_credentials.h
  // nonrev_credential_update(nrc, acc);

  // 5. Select random ... mod q

  // page 7 - 5. Select random ... mod q
  element_random(nrsp_prep->rho);
  element_random(nrsp_prep->rho_apos);
  element_random(nrsp_prep->r);
  element_random(nrsp_prep->r_apos);
  element_random(nrsp_prep->r_apos2);
  element_random(nrsp_prep->r_apos3);
  element_random(nrsp_prep->o);
  element_random(nrsp_prep->o_apos);

  // page 7 - 8. Generate random ... mod q
  element_random(nrsp_prep->rho_tilde);
  element_random(nrsp_prep->o_tilde);
  element_random(nrsp_prep->o_apos_tilde);
  element_random(nrsp_prep->c_tilde);
  element_random(nrsp_prep->m_tilde);
  element_random(nrsp_prep->m_apos_tilde);
  element_random(nrsp_prep->t_tilde);
  element_random(nrsp_prep->t_apos_tilde);
  element_random(nrsp_prep->m2_tilde);
  element_random(nrsp_prep->s_tilde);
  element_random(nrsp_prep->r_tilde);
  element_random(nrsp_prep->r_apos_tilde);
  element_random(nrsp_prep->r_apos2_tilde);
  element_random(nrsp_prep->r_apos3_tilde);

  // 6. Compute
  //    E, D, A, G, W, S, U in Eq. (22) ~ (25)
  element_pow2_zn(nrsp_prep->E, pk->h, nrsp_prep->rho, pk->h_tilde, nrsp_prep->o); // E
  element_pow2_zn(nrsp_prep->D, acc->g, nrsp_prep->r, pk->h_tilde, nrsp_prep->o_apos); // D
  element_pow_zn(nrsp_prep->A, pk->h_tilde, nrsp_prep->rho);
  element_mul(nrsp_prep->A, nrc->sigma, nrsp_prep->A); // A
  element_pow_zn(nrsp_prep->G, pk->h_tilde, nrsp_prep->r);
  element_mul(nrsp_prep->G, nrc->g_i, nrsp_prep->G); // G
  element_pow_zn(nrsp_prep->W, pk->h_caret, nrsp_prep->r_apos);
  element_mul(nrsp_prep->W, nrc->wit_i->w, nrsp_prep->W); // W
  element_pow_zn(nrsp_prep->S, pk->h_caret, nrsp_prep->r_apos2);
  element_mul(nrsp_prep->S, nrc->wit_i->sigma_i, nrsp_prep->S); // S
  element_pow_zn(nrsp_prep->U, pk->h_caret, nrsp_prep->r_apos3);
  element_mul(nrsp_prep->U, nrc->wit_i->u_i, nrsp_prep->U); // U

  // page 7 Eq. (26) (27)
  element_mul(nrsp_prep->m, nrsp_prep->rho, nrc->c);
  element_mul(nrsp_prep->t, nrsp_prep->o, nrc->c);
  element_mul(nrsp_prep->m_apos, nrsp_prep->r, nrsp_prep->r_apos2);
  element_mul(nrsp_prep->t_apos, nrsp_prep->o_apos, nrsp_prep->r_apos2);

  // page 7 Eq. (28) ~ (32)
  element_t t, t1, t2, t3;

  // T1 bar
  element_pow2_zn(nrsp_prep->T_bar[0],
		  pk->h, nrsp_prep->rho_tilde,
		  pk->h_tilde, nrsp_prep->o_tilde);

  // T2 bar
  element_init_same_as(t1, nrsp_prep->T_bar[1]);
  element_init_same_as(t2, nrsp_prep->T_bar[1]);
  element_invert(t1, pk->h);
  element_invert(t2, pk->h_tilde);
  element_pow3_zn(nrsp_prep->T_bar[1],
		  nrsp_prep->E, nrsp_prep->c_tilde,
		  t1, nrsp_prep->m_tilde,
		  t2, nrsp_prep->t_tilde);
  element_clear(t1);
  element_clear(t2);

  // T3 bar
  element_init_same_as(t, nrsp_prep->T_bar[2]);
  element_init_same_as(t1, nrsp_prep->T_bar[2]);
  element_init_same_as(t2, nrsp_prep->T_bar[2]);
  element_init_same_as(t3, nrsp_prep->T_bar[2]);
  element_pairing(t1, nrsp_prep->A, pk->h_caret);
  element_pairing(t2, pk->h_tilde, pk->h_caret);
  element_pairing(t3, pk->h_tilde, pk->y);
  element_invert(t3, t3);
  element_pow3_zn(nrsp_prep->T_bar[2],
		  t1, nrsp_prep->c_tilde,
		  t2, nrsp_prep->r_tilde,
		  t3, nrsp_prep->rho_tilde);
  element_pairing(t1, pk->h_tilde, pk->h_caret);
  element_invert(t1, t1);
  element_pairing(t2, pk->h1, pk->h_caret);
  element_invert(t2, t2);
  element_pairing(t3, pk->h2, pk->h_caret);
  element_invert(t3, t3);
  element_pow3_zn(t,
		  t1, nrsp_prep->m_tilde,
		  t2, nrsp_prep->m2_tilde,
		  t3, nrsp_prep->s_tilde);
  element_mul(nrsp_prep->T_bar[2], nrsp_prep->T_bar[2], t);
  element_clear(t);
  element_clear(t1);
  element_clear(t2);
  element_clear(t3);

  // T4 bar
  element_init_same_as(t, acc->g);
  element_init_same_as(t1, nrsp_prep->T_bar[3]);
  element_init_same_as(t2, nrsp_prep->T_bar[3]);
  element_pairing(t1, pk->h_tilde, acc->acc);
  element_invert(t, acc->g);
  element_pairing(t2, t, pk->h_caret);
  element_pow2_zn(nrsp_prep->T_bar[3],
		  t1, nrsp_prep->r_tilde, 
		  t2, nrsp_prep->r_apos_tilde);
  element_clear(t);
  element_clear(t1);
  element_clear(t2);  

  // T5 bar
  element_pow2_zn(nrsp_prep->T_bar[4],
		  acc->g, nrsp_prep->r_tilde,
		  pk->h_tilde, nrsp_prep->o_apos_tilde);

  // T6 bar
  element_init_same_as(t1, nrsp_prep->T_bar[5]);
  element_init_same_as(t2, nrsp_prep->T_bar[5]);
  element_invert(t1, acc->g);
  element_invert(t2, pk->h_tilde);
  element_pow3_zn(nrsp_prep->T_bar[5],
		  nrsp_prep->D, nrsp_prep->r_apos2_tilde,
		  t1, nrsp_prep->m_apos_tilde,
		  t2, nrsp_prep->t_apos_tilde);
  element_clear(t1);
  element_clear(t2);

  // T7 bar
  element_init_same_as(t, pk->pk);
  element_init_same_as(t1, nrsp_prep->T_bar[6]);
  element_init_same_as(t2, nrsp_prep->T_bar[6]);
  element_init_same_as(t3, nrsp_prep->T_bar[6]);
  element_mul(t, pk->pk, nrsp_prep->G);
  element_pairing(t1, t, pk->h_caret);
  element_pairing(t2, pk->h_tilde, pk->h_caret);
  element_invert(t2, t2);
  element_pairing(t3, pk->h_tilde, nrsp_prep->S);
  element_pow3_zn(nrsp_prep->T_bar[6],
		  t1, nrsp_prep->r_apos2_tilde,
		  t2, nrsp_prep->m_apos_tilde,
		  t3, nrsp_prep->r_tilde);
  element_clear(t);
  element_clear(t1);
  element_clear(t2);
  element_clear(t3);

  // T8 bar
  element_init_same_as(t, acc->g);
  element_init_same_as(t1, nrsp_prep->T_bar[7]);
  element_init_same_as(t2, nrsp_prep->T_bar[7]);
  element_pairing(t1, pk->h_tilde, pk->u);
  element_invert(t, acc->g);
  element_pairing(t2, t, pk->h_caret);
  element_pow2_zn(nrsp_prep->T_bar[7],
		  t1, nrsp_prep->r_tilde,
		  t2, nrsp_prep->r_apos3_tilde);
}

void nonrev_subproof_prepare_into_CT
(mpz_vec_t C,  // OUT
 mpz_vec_t T, // OUT
 nonrev_subproof_prepare_t nrsp_prep)
{
  mpz_t t;
  mpz_init(t);

  // into C
  element_to_mpz(t, nrsp_prep->E);
  mpz_vec_append(C, t);
  element_to_mpz(t, nrsp_prep->D);
  mpz_vec_append(C, t);
  element_to_mpz(t, nrsp_prep->A);
  mpz_vec_append(C, t);
  element_to_mpz(t, nrsp_prep->G);
  mpz_vec_append(C, t);
  element_to_mpz(t, nrsp_prep->W);
  mpz_vec_append(C, t);
  element_to_mpz(t, nrsp_prep->S);
  mpz_vec_append(C, t);
  element_to_mpz(t, nrsp_prep->U);
  mpz_vec_append(C, t);

  // into T
  for (unsigned long i = 0; i < 8; ++i) {
    element_to_mpz(t, nrsp_prep->T_bar[i]);
    mpz_vec_append(T, t);
  }

  mpz_clear(t);
}

void nonrev_subproof_init(nonrev_subproof_t nrsp,
			  pairing_t pairing)
{
  element_init_Zr(nrsp->rho_caret, pairing);
  element_init_Zr(nrsp->o_caret, pairing);
  element_init_Zr(nrsp->c_caret, pairing);
  element_init_Zr(nrsp->o_apos_caret, pairing);
  element_init_Zr(nrsp->m_caret, pairing);
  element_init_Zr(nrsp->m_apos_caret, pairing);
  element_init_Zr(nrsp->t_caret, pairing);
  element_init_Zr(nrsp->t_apos_caret, pairing);
  element_init_Zr(nrsp->m2_caret, pairing);
  element_init_Zr(nrsp->s_caret, pairing);
  element_init_Zr(nrsp->r_caret, pairing);
  element_init_Zr(nrsp->r_apos_caret, pairing);
  element_init_Zr(nrsp->r_apos2_caret, pairing);
  element_init_Zr(nrsp->r_apos3_caret, pairing);
}

void nonrev_subproof_assign
(nonrev_subproof_t nrsp,
 mpz_t CH,
 mpz_t m2,
 nonrev_credential_t nrc,
 nonrev_subproof_prepare_t nrsp_prep)
{
  element_t t, eCH, em2;
  element_init_same_as(  t, nrsp->rho_caret);
  element_init_same_as(eCH, nrsp->rho_caret);
  element_init_same_as(em2, nrsp->rho_caret);
  element_set_mpz(eCH, CH);
  element_set_mpz(em2, m2);

  // line 1
  element_mul(t, eCH, nrsp_prep->rho);
  element_sub(nrsp->rho_caret, nrsp_prep->rho_tilde, t);
  element_mul(t, eCH, nrsp_prep->o);
  element_sub(nrsp->o_caret, nrsp_prep->o_tilde, t);

  // line 2
  element_mul(t, eCH, nrc->c);
  element_sub(nrsp->c_caret, nrsp_prep->c_tilde, t);
  element_mul(t, eCH, nrsp_prep->o_apos);
  element_sub(nrsp->o_caret, nrsp_prep->o_tilde, t);

  // line 3
  element_mul(t, eCH, nrsp_prep->m);
  element_sub(nrsp->m_caret, nrsp_prep->m_tilde, t);
  element_mul(t, eCH, nrsp_prep->m_apos);
  element_sub(nrsp->m_caret, nrsp_prep->m_apos_tilde, t);

  // line 4
  element_mul(t, eCH, nrsp_prep->t);
  element_sub(nrsp->t_caret, nrsp_prep->t_tilde, t);
  element_mul(t, eCH, nrsp_prep->t_apos);
  element_sub(nrsp->t_apos_caret, nrsp_prep->t_apos_tilde, t);

  // line 5
  element_set_mpz(t, m2);
  element_mul(t, eCH, t);
  element_sub(nrsp->m2_caret, nrsp_prep->m2_tilde, t);
  element_mul(t, eCH, nrc->s);
  element_sub(nrsp->s_caret, nrsp_prep->s_tilde, t);

  // line 6
  element_mul(t, eCH, nrsp_prep->r);
  element_sub(nrsp->r_caret, nrsp_prep->r_tilde, t);
  element_mul(t, eCH, nrsp_prep->r_apos);
  element_sub(nrsp->r_apos_caret, nrsp_prep->r_apos_tilde, t);

  // line 7
  element_mul(t, eCH, nrsp_prep->r_apos2);
  element_sub(nrsp->r_apos2_caret, nrsp_prep->r_apos2_tilde, t);
  element_mul(t, eCH, nrsp_prep->r_apos3);
  element_sub(nrsp->r_apos3_caret, nrsp_prep->r_apos3_tilde, t);

  element_clear(t);
  element_clear(eCH);
  element_clear(em2);
}
