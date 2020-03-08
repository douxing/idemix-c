#include "idemix_credentials.h"

void primary_pre_credential_prepare_init
(pri_pre_cred_prep_t ppc_prep,
 schema_t s)
{
  mpz_inits(ppc_prep->U,
	    ppc_prep->c,
	    ppc_prep->v_apos_caret,
	    ppc_prep->n1);
  attr_vec_init(ppc_prep->av, schema_attr_cnt_hidden(s));
}


void non_revok_pre_credential_prepare_init
(nr_pre_cred_prep_t nrpc_prep,
 pairing_t pairing)
{
  element_init_G1(nrpc_prep->U, pairing);
}

void primary_pre_credential_init
(pri_pre_cred_t ppc,
 schema_t s)
{
  mpz_inits(ppc->A,
	    ppc->e,
	    ppc->v_apos_apos,
	    ppc->s_e,
	    ppc->c_apos);
  attr_vec_init(ppc->av, schema_attr_cnt_known(s));
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


void primary_credential_init
(pri_cred_t pc,
 schema_t s)
{
  mpz_inits(pc->e, pc->A, pc->v);
  attr_vec_init(pc->av, s->l);
}

void non_revok_credential_init(nr_cred_t nrc, pairing_t pairing)
{
  // initialized pairing members
  element_init_GT(nrc->IA, pairing);
  element_init_G1(nrc->sigma, pairing);
  element_init_Zr(nrc->c, pairing);
  element_init_Zr(nrc->s, pairing);

  witness_init(nrc->wit_i, pairing);

  element_init_G1(nrc->g_i, pairing);
  element_init_G2(nrc->g_apos_i, pairing);
}

void non_revok_credential_update
(nr_cred_t nrc, // cnr->wit_i->V as V_old
 accumulator_t acc)
{
  unsigned long L = acc->L;
  index_vec_ptr V = acc->V;
  index_vec_ptr Vold = nrc->wit_i->V;

  unsigned long max_next_index = // first iterate end
    index_vec_next_index(V) > index_vec_next_index(Vold) ?
    index_vec_next_index(V) : index_vec_next_index(V);

  for (unsigned long j = 0; j < max_next_index; ++j) {
    if (nrc->i != j) {
      continue;
    }

    if (index_vec_is_set(V, j) && !index_vec_is_set(Vold, j)) {
      element_mul(nrc->wit_i->w, nrc->wit_i->w, acc->g2_v[L - j + nrc->i]);
    } else if (!index_vec_is_set(V, j) && index_vec_is_set(Vold, j)) {
      element_div(nrc->wit_i->w, nrc->wit_i->w, acc->g2_v[L - j + nrc->i]);
    }
  }

  index_vec_clone(Vold, V);
}
