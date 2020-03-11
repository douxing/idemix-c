#include "idemix_non_revocation_credential_subproof_auxiliary.h"

void nonrev_credential_subproof_auxiliary_init
(nonrev_credential_subproof_auxiliary_t nrcspa,
 pairing_t pairing)
{
  element_init_Zr(nrcspa->rho, pairing);
  element_init_Zr(nrcspa->rho_apos, pairing);
  element_init_Zr(nrcspa->r, pairing);
  element_init_Zr(nrcspa->r_apos, pairing);
  element_init_Zr(nrcspa->r_apos2, pairing);
  element_init_Zr(nrcspa->r_apos3, pairing);
  element_init_Zr(nrcspa->o, pairing);
  element_init_Zr(nrcspa->o_apos, pairing);

  element_init_Zr(nrcspa->rho_tilde, pairing);
  element_init_Zr(nrcspa->o_tilde, pairing);
  element_init_Zr(nrcspa->o_apos_tilde, pairing);
  element_init_Zr(nrcspa->c_tilde, pairing);
  element_init_Zr(nrcspa->m_tilde, pairing);
  element_init_Zr(nrcspa->m_apos_tilde, pairing);
  element_init_Zr(nrcspa->t_tilde, pairing);
  element_init_Zr(nrcspa->t_apos_tilde, pairing);
  element_init_Zr(nrcspa->m2_tilde, pairing);
  element_init_Zr(nrcspa->s_tilde, pairing);
  element_init_Zr(nrcspa->r_tilde, pairing);
  element_init_Zr(nrcspa->r_apos_tilde, pairing);
  element_init_Zr(nrcspa->r_apos2_tilde, pairing);
  element_init_Zr(nrcspa->r_apos3_tilde, pairing);

  element_init_Zr(nrcspa->m, pairing);
  element_init_Zr(nrcspa->t, pairing);
  element_init_Zr(nrcspa->m_apos, pairing);
  element_init_Zr(nrcspa->t_apos, pairing);
}

void nonrev_credential_subproof_auxiliary_clear
(nonrev_credential_subproof_auxiliary_t nrcspa)
{
  element_clear(nrcspa->rho);
  element_clear(nrcspa->rho_apos);
  element_clear(nrcspa->r);
  element_clear(nrcspa->r_apos);
  element_clear(nrcspa->r_apos2);
  element_clear(nrcspa->r_apos3);
  element_clear(nrcspa->o);
  element_clear(nrcspa->o_apos);

  element_clear(nrcspa->rho_tilde);
  element_clear(nrcspa->o_tilde);
  element_clear(nrcspa->o_apos_tilde);
  element_clear(nrcspa->c_tilde);
  element_clear(nrcspa->m_tilde);
  element_clear(nrcspa->m_apos_tilde);
  element_clear(nrcspa->t_tilde);
  element_clear(nrcspa->t_apos_tilde);
  element_clear(nrcspa->m2_tilde);
  element_clear(nrcspa->s_tilde);
  element_clear(nrcspa->r_tilde);
  element_clear(nrcspa->r_apos_tilde);
  element_clear(nrcspa->r_apos2_tilde);
  element_clear(nrcspa->r_apos3_tilde);

  element_clear(nrcspa->m);
  element_clear(nrcspa->t);
  element_clear(nrcspa->m_apos);
  element_clear(nrcspa->t_apos);
}

void nonrev_credential_subproof_auxiliary_assign
(nonrev_credential_subproof_auxiliary_t nrcspa,
 nonrev_credential_t nrc)
{
  // page 7 - 5. Select auxiliary ... mod q
  element_random(nrcspa->rho);
  element_random(nrcspa->rho_apos);
  element_random(nrcspa->r);
  element_random(nrcspa->r_apos);
  element_random(nrcspa->r_apos2);
  element_random(nrcspa->r_apos3);
  element_random(nrcspa->o);
  element_random(nrcspa->o_apos);

  // page 7 - 8. Generate random ... mod q
  element_random(nrcspa->rho_tilde);
  element_random(nrcspa->o_tilde);
  element_random(nrcspa->o_apos_tilde);
  element_random(nrcspa->c_tilde);
  element_random(nrcspa->m_tilde);
  element_random(nrcspa->m_apos_tilde);
  element_random(nrcspa->t_tilde);
  element_random(nrcspa->t_apos_tilde);
  element_random(nrcspa->m2_tilde);
  element_random(nrcspa->s_tilde);
  element_random(nrcspa->r_tilde);
  element_random(nrcspa->r_apos_tilde);
  element_random(nrcspa->r_apos2_tilde);
  element_random(nrcspa->r_apos3_tilde);

  // page 7 Eq. (26) (27)
  element_mul(nrcspa->m, nrcspa->rho, nrc->c);
  element_mul(nrcspa->t, nrcspa->o, nrc->c);
  element_mul(nrcspa->m_apos, nrcspa->r, nrcspa->r_apos2);
  element_mul(nrcspa->t_apos, nrcspa->o_apos, nrcspa->r_apos2);
}
