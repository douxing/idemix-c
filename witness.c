#include "idemix_witness.h"

void witness_init(witness_t wit, // OUTPUT
		  pairing_t pairing)
{
  element_init_G2(wit->sigma_i, pairing);
  element_init_G2(wit->u_i, pairing);
  element_init_G1(wit->g_i, pairing);
  element_init_G2(wit->w, pairing);
  bitmap_init(wit->V);
}

void witness_clear(witness_t wit)
{
  element_clear(wit->sigma_i);
  element_clear(wit->u_i);
  element_clear(wit->g_i);
  element_clear(wit->w);
  bitmap_clear(wit->V);
}
