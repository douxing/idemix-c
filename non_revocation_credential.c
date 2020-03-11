#include "idemix_non_revocation_credential.h"

void nonrev_pre_credential_prepare_init
(nonrev_pre_credential_prepare_t nrpc_prep,
 pairing_t pairing)
{
  element_init_G1(nrpc_prep->U, pairing);
}

void nonrev_pre_credential_prepare_clear
(nonrev_pre_credential_prepare_t nrpc_prep)
{
  element_clear(nrpc_prep->U);
}

void nonrev_pre_credential_init(nonrev_pre_credential_t nrpc, // OUT
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

void nonrev_pre_credential_clear
(nonrev_pre_credential_t nrpc)
{
  // initialized pairing members
  element_clear(nrpc->IA);
  element_clear(nrpc->sigma);
  element_clear(nrpc->c);
  element_clear(nrpc->s_apos_apos);

  witness_clear(nrpc->wit_i);

  element_clear(nrpc->g_i);
  element_clear(nrpc->g_apos_i);
}

void nonrev_credential_init(nonrev_credential_t nrc,
			    pairing_t pairing)
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

void nonrev_credential_clear(nonrev_credential_t nrc)
{
  element_clear(nrc->IA);
  element_clear(nrc->sigma);
  element_clear(nrc->c);
  element_clear(nrc->s);

  witness_clear(nrc->wit_i);

  element_clear(nrc->g_i);
  element_clear(nrc->g_apos_i);
}

// 7.2 item.4 page 7
void nonrev_credential_update
(nonrev_credential_t nrc, // nrc->wit_i->V as V_old
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
