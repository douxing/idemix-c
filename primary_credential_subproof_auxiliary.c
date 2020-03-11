#include "idemix_primary_credential_subproof_auxiliary.h"
#include "idemix_random.h"

void primary_credential_subproof_auxiliary_init
(primary_credential_subproof_auxiliary_t pcspa)
{
  mpz_inits(pcspa->r,
	    pcspa->v_apos,
	    pcspa->e_apos,
	    pcspa->v_tilde,
	    pcspa->e_tilde);
}

void primary_credential_subproof_auxiliary_clear
(primary_credential_subproof_auxiliary_t pcspa)
{
  mpz_clears(pcspa->r,
	     pcspa->v_apos,
	     pcspa->e_apos,
	     pcspa->v_tilde,
	     pcspa->e_tilde);
}

void primary_credential_subproof_auxiliary_assign
(primary_credential_subproof_auxiliary_t pcspa,
 primary_credential_t pc)
{
  random_num_exact_bits(pcspa->r, 2128); // 2.1

  mpz_mul(pcspa->v_apos, pc->e, pcspa->r);
  mpz_sub(pcspa->v_apos, pc->v, pcspa->v_apos); // v' = v - er

  // 2.3 e' = e - 2^596
  mpz_set_ui(pcspa->e_apos, 0);
  mpz_setbit(pcspa->e_apos, 596);
  mpz_sub(pcspa->e_apos, pc->e, pcspa->e_apos);

  random_num_exact_bits(pcspa->e_tilde, 456);  // 2.4
  random_num_exact_bits(pcspa->v_tilde, 3060); // 2.5
}
