#include "idemix_predicate_subproof_auxiliary.h"
#include "idemix_random.h"
#include "idemix_decompose.h"

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
	    NULL);
}

void predicate_subproof_auxiliary_clear
(predicate_subproof_auxiliary_t pspa)
{
  mpz_clears(pspa->delta,
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
	     NULL);
}

void predicate_subproof_auxiliary_assign
(predicate_subproof_auxiliary_t pspa,
 predicate_t p)
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

  decompose(pspa->u, pspa->delta); // assgin u1 u2 u3 u4

  random_num_exact_bits(pspa->m_tilde, 592); // 7.2.(Validity Proof).1

  random_num_exact_bits(pspa->r_delta, 2128);
  random_num_exact_bits(pspa->r_delta_tilde, 672);

  for (unsigned long i = 0; i < 4; ++i) {
    random_num_exact_bits(pspa->r[i], 2128);    
    random_num_exact_bits(pspa->u_tilde[i], 592);
    random_num_exact_bits(pspa->r_tilde[i], 672);
  }

  random_num_exact_bits(pspa->alpha_tilde, 2787);
}
