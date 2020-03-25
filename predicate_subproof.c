#include "idemix_random.h"
#include "idemix_predicate_subproof.h"

void predicate_subproof_init
(predicate_subproof_t psp)
{
  mpz_inits(psp->u_caret[0],
	    psp->u_caret[1],
	    psp->u_caret[2],
	    psp->u_caret[3],
	    psp->r_caret[0],
	    psp->r_caret[1],
	    psp->r_caret[2],
	    psp->r_caret[3],
	    psp->r_delta_caret,
	    psp->alpha_caret,
	    psp->m_caret,
	    NULL);
}

void predicate_subproof_clear
(predicate_subproof_t psp)
{
  mpz_clears(psp->u_caret[0],
	     psp->u_caret[1],
	     psp->u_caret[2],
	     psp->u_caret[3],
	     psp->r_caret[0],
	     psp->r_caret[1],
	     psp->r_caret[2],
	     psp->r_caret[3],
	     psp->r_delta_caret,
	     psp->alpha_caret,
	     psp->m_caret,
	     NULL);
}

void predicate_subproof_assign
(predicate_subproof_t psp,
 mpz_t CH,
 predicate_t p,
 predicate_subproof_auxiliary_t pspa)
{
  mpz_t t;
  mpz_init(t);
  mpz_set(psp->alpha_caret, pspa->r_delta); // Eq. (48) 1 / 3

  for (unsigned long i = 0; i < 4; ++i) {
    // Eq. (45)
    mpz_mul(psp->u_caret[i], CH, pspa->u[i]);
    mpz_add(psp->u_caret[i], pspa->u_tilde[i], psp->u_caret[i]);

    // Eq. (46)
    mpz_mul(psp->r_caret[i], CH, pspa->u[i]);
    mpz_add(psp->r_caret[i], pspa->r_tilde[i], psp->r_caret[i]);

    // Eq. (48) 2 / 3
    mpz_mul(t, pspa->u[i], pspa->r[i]);
    mpz_sub(psp->alpha_caret, psp->alpha_caret, t);
  }

  // Eq. (47)
  mpz_mul(psp->r_delta_caret, CH, pspa->r_delta);
  mpz_add(psp->r_delta_caret, pspa->r_delta_tilde, psp->r_delta_caret);

  // Eq. (48) 3 / 3  
  mpz_mul(t, CH, psp->alpha_caret);
  mpz_add(psp->alpha_caret, pspa->alpha_tilde, t);

  // set mj_caret
  mpz_mul(psp->m_caret, CH, p->m);
  mpz_add(psp->m_caret, pspa->m_tilde, psp->m_caret);

  mpz_clear(t);
}
