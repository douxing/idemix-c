#include "idemix_credentials.h"

void primary_pre_credential_prepare_init
(pri_pre_cred_prep_t ppc_prep,
 schema_t s)
{
  mpz_inits(ppc_prep->U,
	    ppc_prep->c,
	    ppc_prep->v_apos_caret,
	    ppc_prep->n1);
  attr_vec_init(ppc_prep->m_carets, schema_attr_cnt_hidden(s));
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
  attr_vec_init(ppc->Ak, schema_attr_cnt_known(s));
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
  attr_vec_init(pc->Cs, s->l);
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
(nr_cred_t nrc, // nrc->wit_i->V as V_old
 accumulator_t acc) // latest accumulator
{
  unsigned long L = acc->L;
  bitmap_ptr V = acc->V;
  bitmap_ptr Vold = nrc->wit_i->V;

  for (unsigned long j = 0; j < L; ++j) {
    if (nrc->i == j) {
      continue;
    }

    if (bitmap_tstbit(V, j) && !bitmap_tstbit(Vold, j)) {
      element_mul(nrc->wit_i->w, nrc->wit_i->w, acc->g2_v[L - j + nrc->i]);
    } else if (!bitmap_tstbit(V, j) && bitmap_tstbit(Vold, j)) {
      element_div(nrc->wit_i->w, nrc->wit_i->w, acc->g2_v[L - j + nrc->i]);
    }
  }

  bitmap_set(Vold, V);
}
