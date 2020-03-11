#include "idemix_predicate_subproof_auxiliary.h"
#include "idemix_random.h"
#include "idemix_utils.h"

void predicate_subproof_auxiliary_init
(predicate_subproof_auxiliary_t pspa)
{
  mpz_inits(pspa->delta,
	    pspa->u[0],
	    pspa->u[1],
	    pspa->u[2],
	    pspa->u[3],
	    pspa->m_tilde,
	    pspa->r_delta,
	    pspa->r[0],
	    pspa->r[1],
	    pspa->r[2],
	    pspa->r[3],
	    pspa->T[0],
	    pspa->T[1],
	    pspa->T[2],
	    pspa->T[3],
	    pspa->T_delta,
	    pspa->u_tilde[0],
	    pspa->u_tilde[1],
	    pspa->u_tilde[2],
	    pspa->u_tilde[3],
	    pspa->r_delta_tilde,
	    pspa->r_tilde[0],
	    pspa->r_tilde[1],
	    pspa->r_tilde[2],
	    pspa->r_tilde[3],
	    pspa->alpha_tilde,
	    pspa->T_bar[0],
	    pspa->T_bar[1],
	    pspa->T_bar[2],
	    pspa->T_bar[3],
	    pspa->T_delta_bar,
	    pspa->Q);
}

void predicate_subproof_auxiliary_assign
(predicate_subproof_auxiliary_t pspa,
 predicate_t p,
 issuer_pk_t pk)
{
  switch (p->op) { // assign delta
  case LESS_THAN_OR_EQUAL_TO:    // m <= z
    mpz_sub(pspa->delta, p->z, p->m);
    break;
  case LESS_THAN:                // m <  z
    mpz_sub(pspa->delta, p->z, p->m);
    mpz_sub_ui(pspa->delta, pspa->delta, 1);
    break;
  case GREATER_THAN_OR_EQUAL_TO: // m >= z
    mpz_sub(pspa->delta, p->m, p->z);
    break;
  case GREATER_THAN:             // m >  z
    mpz_sub(pspa->delta, p->m, p->z);
    mpz_sub_ui(pspa->delta, pspa->delta, 1);
    break;
  default:
    printf("unknown operator: %d", p->op);
    return;
  }
  // assert delta >= 0

  decompose_to_4_squares(pspa->u, pspa->delta); // assgin u1 u2 u3 u4

  random_num_exact_bits(pspa->m_tilde, 592); // 7.2.(Validity Proof).1

  random_num_exact_bits(pspa->r_delta, 2128);
  random_num_exact_bits(pspa->r_delta_tilde, 672);

  for (unsigned long i = 0; i < 4; ++i) {
    random_num_exact_bits(pspa->r[i], 2128);    
    random_num_exact_bits(pspa->u_tilde[i], 592);
    random_num_exact_bits(pspa->r_tilde[i], 672);
  }

  random_num_exact_bits(pspa->alpha_tilde, 2787);

  // Eq. (36) ~ (40)
  mpz_t t;
  mpz_init(t);
  mpz_powm(pspa->Q, pk->S, pspa->alpha_tilde, pk->n); // Eq. (40) 1/2

  // T1~T4 T1bar~T4bar
  for (unsigned long i = 0; i < 4; ++i) {
    // Eq. (36)
    mpz_powm(pspa->T[i], pk->Z, pspa->u[i], pk->n);
    mpz_powm(t, pk->S, pspa->r[i], pk->n);
    mpz_mul(pspa->T[i], pspa->T[i], t);
    mpz_mod(pspa->T[i], pspa->T[i], pk->n);

    // Eq. (38)
    mpz_powm(pspa->T_bar[i], pk->Z, pspa->u_tilde[i], pk->n);
    mpz_powm(t, pk->S, pspa->r_tilde[i], pk->n);
    mpz_mul(pspa->T_bar[i], pspa->T_bar[i], t);
    mpz_mod(pspa->T_bar[i], pspa->T_bar[i], pk->n);

    mpz_powm(t, pspa->T[i], pspa->u_tilde[i], pk->n); // Eq. (40) 2/2
    mpz_mul(pspa->Q, pspa->Q, t);
    mpz_mul(pspa->Q, pspa->Q, pk->n);
  }

  // Eq. (37) T_delta
  mpz_powm(pspa->T_delta, pk->Z, pspa->delta, pk->n);
  mpz_powm(t, pk->S, pspa->r_delta, pk->n);
  mpz_mul(pspa->T_delta, pspa->T_delta, t);
  mpz_mod(pspa->T_delta, pspa->T_delta, pk->n);

  // Eq. (39) T_delta_bar
  mpz_powm(pspa->T_delta_bar, pk->Z, pspa->m_tilde, pk->n);
  mpz_powm(t, pk->S, pspa->r_delta_tilde, pk->n);
  mpz_mul(pspa->T_delta_bar, pspa->T_delta_bar, t);
  mpz_mod(pspa->T_delta_bar, pspa->T_delta_bar, pk->n);
  
  mpz_clear(t);
}
