#include <memory.h>
#include <stdlib.h>

#include "idemix_accumulator.h"

void accumulator_init(accumulator_t acc, // OUTPUT
		      accum_sk_t sk,     // OUTPUT
		      accum_pk_t pk,     // OUTPUT
		      pairing_t pairing,
		      unsigned long L,
		      element_t g,
		      element_t g_apos)
{
  // assert L >= 2;
  acc->L = L;
  element_init_G1(acc->g, pairing);
  element_set(acc->g, g);
  element_init_G2(acc->g_apos, pairing);
  element_set(acc->g_apos, g_apos);

  // 1. Generate random gamma(mod q);
  element_init_Zr(sk->gamma, pairing);
  element_random(sk->gamma);

  // 2. Computes
  // 2.1 g1, ..., g2L and 2.2 g'1, ..., g'2L
  acc->g1_v = (element_t *)malloc(sizeof(element_t) * 2 * L);
  acc->g2_v = (element_t *)malloc(sizeof(element_t) * 2 * L);

  // acc->g1_v[0] = g^gamma
  element_init_G1(acc->g1_v[0], pairing);
  element_pow_zn(acc->g1_v[0], g, sk->gamma);
  // acc->g2_v[0] = g'^gamma
  element_init_G2(acc->g2_v[0], pairing);
  element_pow_zn(acc->g2_v[0], g_apos, sk->gamma);

  unsigned long i = 1;
  while (i < L) { // [1, L - 1]
    element_init_G1(acc->g1_v[i], pairing);
    element_mul(acc->g1_v[i], acc->g1_v[i - 1], acc->g1_v[0]);
    element_init_G2(acc->g2_v[i], pairing);
    element_mul(acc->g2_v[i], acc->g2_v[i - 1], acc->g2_v[0]);
    ++i;
  }

  // (L+1)th element, set to the generator of the corresponding group
  // dx: maybe useless
  element_init_G1(acc->g1_v[L], pairing);
  element_set1(acc->g1_v[L]);
  element_init_G2(acc->g2_v[L], pairing);
  element_set1(acc->g2_v[L]);

  // 2.1 g1, ..., g2L and 2.2 g'1, ..., g'2L, continued
  // (L+2)th element = (L)th element * g^gamma * g^gamma
  element_init_G1(acc->g1_v[L + 1], pairing);
  element_mul(acc->g1_v[L + 1], acc->g1_v[L - 1], acc->g1_v[0]);
  element_mul(acc->g1_v[L + 1], acc->g1_v[L + 1], acc->g1_v[0]);
  element_init_G2(acc->g2_v[L + 1], pairing);
  element_mul(acc->g2_v[L + 1], acc->g1_v[L - 1], acc->g2_v[0]);
  element_mul(acc->g2_v[L + 1], acc->g1_v[L + 1], acc->g2_v[0]);

  // continue from (L+3)th element to the end
  i = L + 2;
  while (i < 2 * L) {
    element_init_G1(acc->g1_v[i], pairing);
    element_mul(acc->g1_v[i], acc->g1_v[i - 1], acc->g1_v[0]);
    element_init_G2(acc->g2_v[i], pairing);
    element_mul(acc->g2_v[i], acc->g2_v[i - 1], acc->g2_v[0]);
    ++i;
  }

  // 2.3 z = (e(g, g'))^gamma^(L+1)
  mpz_t L_plus_one;
  mpz_init_set_ui(L_plus_one, L + 1);

  element_t gamma_pow_L_plus_one;
  element_init_Zr(gamma_pow_L_plus_one, pairing);
  element_pow_mpz(gamma_pow_L_plus_one, sk->gamma, L_plus_one);

  element_init_GT(pk->z, pairing);
  element_pairing(pk->z, g, g_apos);
  element_pow_zn(pk->z, pk->z, gamma_pow_L_plus_one);

  // 3. set V = empty set, acc = 1
  index_vec_init(acc->V);
  element_init_G2(acc->acc, pairing);

  mpz_clear(L_plus_one);
  element_clear(gamma_pow_L_plus_one);
}

void accumulator_clear(accumulator_t acc)
{
  element_clear(acc->g);
  element_clear(acc->g_apos);

  for (mp_bitcnt_t i = 0; i < acc->L * 2; ++i) {
    element_clear(acc->g1_v[i]);
    element_clear(acc->g2_v[i]);
  }
  free(acc->g1_v);
  free(acc->g2_v);

  index_vec_clear(acc->V);
  element_clear(acc->acc);
}

void accumulator_sk_clear(accum_sk_t sk)
{
  element_clear(sk->gamma);
}

void accumulator_pk_clear(accum_pk_t pk)
{
  element_clear(pk->z);
}

