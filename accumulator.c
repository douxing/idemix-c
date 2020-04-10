#include <memory.h>
#include <stdlib.h>

#include "idemix_accumulator.h"

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

  bitmap_clear(acc->V);
  element_clear(acc->acc);
}

void accumulator_sk_clear(accumulator_sk_t sk)
{
  element_clear(sk->gamma);
}

void accumulator_pk_clear(accumulator_pk_t pk)
{
  element_clear(pk->z);
}

void accumulator_init_assign
(accumulator_t acc, // OUTPUT
 accumulator_sk_t sk,     // OUTPUT
 accumulator_pk_t pk,     // OUTPUT
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
    element_pow_zn(acc->g1_v[i], acc->g1_v[i - 1], sk->gamma);
    element_init_G2(acc->g2_v[i], pairing);
    element_pow_zn(acc->g2_v[i], acc->g2_v[i - 1], sk->gamma);
    ++i;
  }

  // (L+1)th element, set to identity
  element_init_G1(acc->g1_v[L], pairing);
  element_set1(acc->g1_v[L]);
  element_init_G2(acc->g2_v[L], pairing);
  element_set1(acc->g2_v[L]);

  // 2.1 g1, ..., g2L and 2.2 g'1, ..., g'2L, continued
  // (L+2)th element = (L)th element * g^gamma * g^gamma
  element_init_G1(acc->g1_v[L + 1], pairing);
  element_pow_zn(acc->g1_v[L + 1], acc->g1_v[L - 1], sk->gamma);
  element_pow_zn(acc->g1_v[L + 1], acc->g1_v[L + 1], sk->gamma);
  element_init_G2(acc->g2_v[L + 1], pairing);
  element_pow_zn(acc->g2_v[L + 1], acc->g2_v[L - 1], sk->gamma);
  element_pow_zn(acc->g2_v[L + 1], acc->g2_v[L + 1], sk->gamma);

  // continue from (L+3)th element to the end
  i = L + 2;
  while (i < 2 * L) {
    element_init_G1(acc->g1_v[i], pairing);
    element_pow_zn(acc->g1_v[i], acc->g1_v[i - 1], sk->gamma);
    element_init_G2(acc->g2_v[i], pairing);
    element_pow_zn(acc->g2_v[i], acc->g2_v[i - 1], sk->gamma);
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
  bitmap_init(acc->V);
  element_init_G2(acc->acc, pairing);
  element_set1(acc->acc);

  mpz_clear(L_plus_one);
  element_clear(gamma_pow_L_plus_one);
}

// Chapter 5:
// initialize w
void compute_w(element_t w, // OUTPUT
	       accumulator_t acc,
	       const unsigned long i)
{
  element_set1(w);
  unsigned long j = bitmap_scan1(acc->V, 0);
  
  // element_printf("frist scan: w: %B\nj: %u\n", w, j);

  while (j < acc->L) {
    if (j != i) {
      element_mul(w, w, acc->g2_v[acc->L - j + i]);
    }
    
    j = bitmap_scan1(acc->V, j + 1);
  }
}

// end of Chapter 5

// Chapter 6

void revoke_index(accumulator_t acc, // OUT
		  const unsigned long index)
{
  // 1. Set V = V\{i}
  bitmap_clrbit(acc->V, index);
  
  // 2. Compute A = A/g'_(L+1-i)
  element_t temp;
  element_init(temp, acc->acc->field);
  element_invert(temp, acc->g2_v[acc->L - index]);
  element_mul(acc->acc, acc->acc, temp);
  element_clear(temp);

  // Publish {V, A}
}

// end of Chapter 6
