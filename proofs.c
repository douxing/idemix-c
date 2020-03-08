#include "idemix_crypto.h"
#include "idemix_random.h"
#include "idemix_proofs.h"
#include "idemix_credentials.h"

#define INIT_AND_RANDOM(e, p)			\
  element_init_Zr(e, p);			\
  element_random(e)

void non_rev_proof_rand_init_with_random(nr_proof_rand_t r, pairing_t p)
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

void primary_proof_init(p_proof_t p)
{
  mpz_inits(p->A_apos,
	    p->v_apos,
	    p->e_apos,
	    p->e_tilde,
	    p->v_tilde,
	    p->T);
}

void p_proof_to_C(mpz_vec_t C, // OUT
		  p_proof_t pp)
{
  mpz_vec_append(C, pp->A_apos);
}

void p_proof_to_T(mpz_vec_t T, // OUT
		  p_proof_t pp)
{
  mpz_vec_append(T, pp->T);
}

void predicate_to_CT(mpz_vec_t C, // OUT
		     mpz_vec_t T, // OUT
		     predicate_t p,
		     iss_pk_t pk,
		     mpz_t mj_tilde)
{
  // Eq. (36) ~ (40)
  mpz_t Q, t, t1, t2;
  mpz_inits(Q, t, t1, t2);
  mpz_powm(Q, pk->S, p->alpha_tilde, pk->n); // Eq. (40)

  // T1
  mpz_powm(t1, pk->Z, p->u1, pk->n);
  mpz_powm(t2, pk->S, p->r1, pk->n);
  mpz_mul(t, t1, t2);
  mpz_mod(t, t, pk->n);
  mpz_vec_append(C, t);
  mpz_powm(t, t, p->u1_tilde, pk->n); // Eq. (40)
  mpz_mul(Q, Q, t);
  mpz_mul(Q, Q, pk->n);

  // T2
  mpz_powm(t1, pk->Z, p->u2, pk->n);
  mpz_powm(t2, pk->S, p->r2, pk->n);
  mpz_mul(t, t1, t2);
  mpz_mod(t, t, pk->n);
  mpz_vec_append(C, t);
  mpz_powm(t, t, p->u2_tilde, pk->n); // Eq. (40)
  mpz_mul(Q, Q, t);
  mpz_mul(Q, Q, pk->n);

  // T3
  mpz_powm(t1, pk->Z, p->u3, pk->n);
  mpz_powm(t2, pk->S, p->r3, pk->n);
  mpz_mul(t, t1, t2);
  mpz_mod(t, t, pk->n);
  mpz_vec_append(C, t);
  mpz_powm(t, t, p->u3_tilde, pk->n); // Eq. (40)
  mpz_mul(Q, Q, t);
  mpz_mul(Q, Q, pk->n);

  // T4
  mpz_powm(t1, pk->Z, p->u4, pk->n);
  mpz_powm(t2, pk->S, p->r4, pk->n);
  mpz_mul(t, t1, t2);
  mpz_mod(t, t, pk->n);
  mpz_vec_append(C, t);
  mpz_powm(t, t, p->u4_tilde, pk->n); // Eq. (40)
  mpz_mul(Q, Q, t);
  mpz_mul(Q, Q, pk->n);

  // T_delta
  mpz_powm(t1, pk->Z, p->delta, pk->n);
  mpz_powm(t2, pk->S, p->r_delta, pk->n);
  mpz_mul(t, t1, t2);
  mpz_mod(t, t, pk->n);
  mpz_vec_append(C, t);

  // T1_bar
  mpz_powm(t1, pk->Z, p->u1_tilde, pk->n);
  mpz_powm(t2, pk->S, p->r1_tilde, pk->n);
  mpz_mul(t, t1, t2);
  mpz_mod(t, t, pk->n);
  mpz_vec_append(T, t);

  // T2_bar
  mpz_powm(t1, pk->Z, p->u2_tilde, pk->n);
  mpz_powm(t2, pk->S, p->r2_tilde, pk->n);
  mpz_mul(t, t1, t2);
  mpz_mod(t, t, pk->n);
  mpz_vec_append(T, t);

  // T3_bar
  mpz_powm(t1, pk->Z, p->u3_tilde, pk->n);
  mpz_powm(t2, pk->S, p->r3_tilde, pk->n);
  mpz_mul(t, t1, t2);
  mpz_mod(t, t, pk->n);
  mpz_vec_append(T, t);

  // T4_bar
  mpz_powm(t1, pk->Z, p->u4_tilde, pk->n);
  mpz_powm(t2, pk->S, p->r4_tilde, pk->n);
  mpz_mul(t, t1, t2);
  mpz_mod(t, t, pk->n);
  mpz_vec_append(T, t);

  // T_delta_bar
  mpz_powm(t1, pk->Z, mj_tilde, pk->n);
  mpz_powm(t2, pk->S, p->r_delta_tilde, pk->n);
  mpz_mul(t, t1, t2);
  mpz_mod(t, t, pk->n);
  mpz_vec_append(T, t);
  
  mpz_vec_append(T, Q);
  mpz_clears(Q, t, t1, t2);
}
