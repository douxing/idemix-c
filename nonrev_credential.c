#include "idemix_nonrev_credential.h"
#include "idemix_random.h"

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

void nonrev_credential_assign
(nonrev_credential_t nrc,
 element_t s_apos,
 nonrev_pre_credential_t nrpc)
{
  element_set(nrc->IA, nrpc->IA);
  element_set(nrc->sigma, nrpc->sigma);
  element_set(nrc->c, nrpc->c);
  element_add(nrc->s, s_apos, nrpc->s_apos_apos);

  witness_set(nrc->wit_i, nrpc->wit_i);
  
  element_set(nrc->g_i, nrpc->g_i);
  element_set(nrc->g_apos_i, nrpc->g_apos_i);
  nrc->i = nrpc->i;
}

// 7.2 item.4 page 7
// update w and V
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
