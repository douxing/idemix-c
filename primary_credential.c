#include "idemix_primary_credential.h"

void primary_pre_credential_prepare_init
(primary_pre_credential_prepare_t ppc_prep,
 schema_t s)
{
  mpz_inits(ppc_prep->U,
	    ppc_prep->c,
	    ppc_prep->v_apos_caret,
	    ppc_prep->n1);
  attr_vec_init(ppc_prep->m_carets, schema_attr_cnt_hidden(s));
}

void primary_pre_credential_init
(primary_pre_credential_t ppc,
 schema_t s)
{
  mpz_inits(ppc->A,
	    ppc->e,
	    ppc->v_apos_apos,
	    ppc->s_e,
	    ppc->c_apos);
  attr_vec_init(ppc->Ak, schema_attr_cnt_known(s));
}


void primary_credential_init
(primary_credential_t pc,
 schema_t s) // l = |Cs| in the schema
{
  mpz_inits(pc->e, pc->A, pc->v);
  attr_vec_init(pc->Cs, s->l);
}
