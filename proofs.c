#include "idemix_crypto.h"
#include "idemix_random.h"
#include "idemix_proofs.h"
#include "idemix_credentials.h"

#define INIT_AND_RANDOM(e, p)			\
  element_init_Zr(e, p);			\
  element_random(e)

void random_proof_randomness(proof_randomness_t r, pairing_t p)
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

void non_revok_proof_init(nr_proof_t nrp, pairing_t p)
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

void nrp_to_C(mpz_vec_t C, // OUT
	      nr_proof_t nrp)
{
  mpz_t t;
  mpz_init(t);
  element_to_mpz(t, nrp->E);
  mpz_vec_append(C, t);
  element_to_mpz(t, nrp->D);
  mpz_vec_append(C, t);
  element_to_mpz(t, nrp->A);
  mpz_vec_append(C, t);
  element_to_mpz(t, nrp->G);
  mpz_vec_append(C, t);
  element_to_mpz(t, nrp->W);
  mpz_vec_append(C, t);
  element_to_mpz(t, nrp->S);
  mpz_vec_append(C, t);
  element_to_mpz(t, nrp->U);
  mpz_vec_append(C, t);
}

void nrp_to_T(mpz_vec_t T, // OUT
	      nr_proof_t nrp)
{
  mpz_t t;
  mpz_init(t);
  element_to_mpz(t, nrp->T1_bar);
  mpz_vec_append(T, t);
  element_to_mpz(t, nrp->T2_bar);
  mpz_vec_append(T, t);
  element_to_mpz(t, nrp->T3_bar);
  mpz_vec_append(T, t);
  element_to_mpz(t, nrp->T4_bar);
  mpz_vec_append(T, t);
  element_to_mpz(t, nrp->T5_bar);
  mpz_vec_append(T, t);
  element_to_mpz(t, nrp->T6_bar);
  mpz_vec_append(T, t);
  element_to_mpz(t, nrp->T7_bar);
  mpz_vec_append(T, t);
  element_to_mpz(t, nrp->T8_bar);
  mpz_vec_append(T, t);
}

