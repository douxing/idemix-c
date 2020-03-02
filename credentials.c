#include "idemix_credentials.h"

void primary_pre_credential_prepare_init(pri_pre_cred_prep_t ppc_prep)
{
  mpz_inits(ppc_prep->U,
	    ppc_prep->c,
	    ppc_prep->v_apos_caret,
	    ppc_prep->m1_caret,
	    ppc_prep->n1);
}


void non_revok_pre_credential_prepare_init(nr_pre_cred_prep_t nrpc_prep,
					   pairing_t pairing)
{
  element_init_G1(nrpc_prep->U, pairing);
}

void primary_pre_credential_init(pri_pre_cred_t ppc)
{
  mpz_inits(ppc->A,
	    ppc->e,
	    ppc->v_apos_apos,
	    ppc->s_e,
	    ppc->c_apos);
}

void non_revok_pre_credential_init(nr_pre_cred_t nrpc, // OUT
				   pairing_t pairing)
{
  // initialized pairing members
  element_init_GT(nrpc->IA, pairing);
  element_init_G1(nrpc->sigma, pairing);
  element_init_Zr(nrpc->c, pairing);
  element_init_Zr(nrpc->s_apos_apos, pairing);

  witness_init(nrpc->wit_i, pairing);

  element_init_G1(nrpc->g_i, pairing);
  element_init_G2(nrpc->g_apos_i, pairing);
}

void primary_credential_init(pri_cred_t pr)
{
  mpz_inits(pr->m1, pr->e, pr->A, pr->v);
}
