#include "idemix_nonrev_credential_subproof.h"

void tuple_x_init
(tuple_x_t X,
 pairing_t pairing)
{
  element_init_Zr(X->rho_caret, pairing);
  element_init_Zr(X->o_caret, pairing);
  element_init_Zr(X->c_caret, pairing);
  element_init_Zr(X->o_apos_caret, pairing);
  element_init_Zr(X->m_caret, pairing);
  element_init_Zr(X->m_apos_caret, pairing);
  element_init_Zr(X->t_caret, pairing);
  element_init_Zr(X->t_apos_caret, pairing);
  element_init_Zr(X->m2_caret, pairing);
  element_init_Zr(X->s_caret, pairing);
  element_init_Zr(X->r_caret, pairing);
  element_init_Zr(X->r_apos_caret, pairing);
  element_init_Zr(X->r_apos2_caret, pairing);
  element_init_Zr(X->r_apos3_caret, pairing);
}

void tuple_x_clear(tuple_x_t X)
{
  element_clear(X->rho_caret);
  element_clear(X->o_caret);
  element_clear(X->c_caret);
  element_clear(X->o_apos_caret);
  element_clear(X->m_caret);
  element_clear(X->m_apos_caret);
  element_clear(X->t_caret);
  element_clear(X->t_apos_caret);
  element_clear(X->m2_caret);
  element_clear(X->s_caret);
  element_clear(X->r_caret);
  element_clear(X->r_apos_caret);
  element_clear(X->r_apos2_caret);
  element_clear(X->r_apos3_caret);
}

void tuple_x_assign
(tuple_x_t X,
 mpz_t CH,
 mpz_t m2,
 nonrev_credential_t nrc,
 nonrev_credential_subproof_auxiliary_t nrcspa)
{
  element_t t, eCH, em2;
  element_init_same_as(  t, X->rho_caret);
  element_init_same_as(eCH, X->rho_caret);
  element_init_same_as(em2, X->rho_caret);
  element_set_mpz(eCH, CH);
  element_set_mpz(em2, m2);

  // line 1
  element_mul(t, eCH, nrcspa->rho);
  element_sub(X->rho_caret, nrcspa->rho_tilde, t);
  element_mul(t, eCH, nrcspa->o);
  element_sub(X->o_caret, nrcspa->o_tilde, t);

  // line 2
  element_mul(t, eCH, nrc->c);
  element_sub(X->c_caret, nrcspa->c_tilde, t);
  element_mul(t, eCH, nrcspa->o_apos);
  element_sub(X->o_apos_caret, nrcspa->o_tilde, t);

  // line 3
  element_mul(t, eCH, nrcspa->m);
  element_sub(X->m_caret, nrcspa->m_tilde, t);
  element_mul(t, eCH, nrcspa->m_apos);
  element_sub(X->m_caret, nrcspa->m_apos_tilde, t);

  // line 4
  element_mul(t, eCH, nrcspa->t);
  element_sub(X->t_caret, nrcspa->t_tilde, t);
  element_mul(t, eCH, nrcspa->t_apos);
  element_sub(X->t_apos_caret, nrcspa->t_apos_tilde, t);

  // line 5
  element_set_mpz(t, m2);
  element_mul(t, eCH, t);
  element_sub(X->m2_caret, nrcspa->m2_tilde, t);
  element_mul(t, eCH, nrc->s);
  element_sub(X->s_caret, nrcspa->s_tilde, t);

  // line 6
  element_mul(t, eCH, nrcspa->r);
  element_sub(X->r_caret, nrcspa->r_tilde, t);
  element_mul(t, eCH, nrcspa->r_apos);
  element_sub(X->r_apos_caret, nrcspa->r_apos_tilde, t);

  // line 7
  element_mul(t, eCH, nrcspa->r_apos2);
  element_sub(X->r_apos2_caret, nrcspa->r_apos2_tilde, t);
  element_mul(t, eCH, nrcspa->r_apos3);
  element_sub(X->r_apos3_caret, nrcspa->r_apos3_tilde, t);

  element_clear(t);
  element_clear(eCH);
  element_clear(em2);
}

void tuple_x_into_vec(mpz_vec_t v, tuple_x_t X)
{
  mpz_t t;
  mpz_init(t);

  element_to_mpz(t, X->rho_caret);
  mpz_vec_append(v, t);
  element_to_mpz(t, X->o_caret);
  mpz_vec_append(v, t);

  element_to_mpz(t, X->c_caret);
  mpz_vec_append(v, t);
  element_to_mpz(t, X->o_apos_caret);
  mpz_vec_append(v, t);

  element_to_mpz(t, X->m_caret);
  mpz_vec_append(v, t);
  element_to_mpz(t, X->m_apos_caret);
  mpz_vec_append(v, t);

  element_to_mpz(t, X->t_caret);
  mpz_vec_append(v, t);
  element_to_mpz(t, X->t_apos_caret);
  mpz_vec_append(v, t);

  element_to_mpz(t, X->m2_caret);
  mpz_vec_append(v, t);
  element_to_mpz(t, X->s_caret);
  mpz_vec_append(v, t);

  element_to_mpz(t, X->r_caret);
  mpz_vec_append(v, t);
  element_to_mpz(t, X->r_apos_caret);
  mpz_vec_append(v, t);

  element_to_mpz(t, X->r_apos2_caret);
  mpz_vec_append(v, t);
  element_to_mpz(t, X->r_apos3_caret);
  mpz_vec_append(v, t);

  mpz_clear(t);
}
