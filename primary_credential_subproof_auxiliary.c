#include <assert.h>
#include "idemix_primary_credential_subproof_auxiliary.h"
#include "idemix_random.h"

void primary_credential_subproof_auxiliary_init
(primary_credential_subproof_auxiliary_t aux)
{
  mpz_inits(aux->r,
	    aux->v_apos,
	    aux->e_apos,
	    aux->v_tilde,
	    aux->e_tilde,
	    NULL);
}

void primary_credential_subproof_auxiliary_clear
(primary_credential_subproof_auxiliary_t aux)
{
  mpz_clears(aux->r,
	     aux->v_apos,
	     aux->e_apos,
	     aux->v_tilde,
	     aux->e_tilde,
	     NULL);
}


void primary_credential_subproof_auxiliary_assign
(primary_credential_subproof_auxiliary_t aux,
 primary_credential_t pc)
{
  random_num_exact_bits(aux->r, 2128);
  mpz_mul(aux->v_apos, pc->e, aux->r);
  mpz_sub(aux->v_apos, pc->v, aux->v_apos);
  assert(mpz_tstbit(pc->e, 596));
  mpz_set(aux->e_apos, pc->e);
  mpz_clrbit(aux->e_apos, 596);
  random_num_exact_bits(aux->e_tilde, 456);
  random_num_exact_bits(aux->v_tilde, 3060);
}
