#include "idemix_accumulator.h"

// section 4.4.1 New Accumulator Setup
void accumulator_setup(pairing_t pairing, unsigned long L,
		       element_t g, element_t g_apos,
		       accum_pk_t pk, accum_sk_t sk, accumulator_t acc)
{
  // assert L >= 2;

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
  element_pow_zn(acc->g2_v[0], g, sk->gamma);

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
  element_set(acc->g1_v[L], g);
  element_init_G2(acc->g2_v[L], pairing);
  element_set(acc->g2_v[L], g_apos);

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
  init_index_vec(acc->V, L);
  element_init_G2(acc->acc, pairing);
}

void compute_omega(element_t omega, accumulator_t acc, unsigned long i)
{
  element_set1(omega);
  for (unsigned long j = 0; j < acc->V->cap * 8; ++j) {
    // assert i != j
    unsigned long sub_i = acc->L + 1 - j + i;
    element_mul(omega, omega, acc->g2_v[sub_i]);
  }
}

void init_index_vec(index_vec_t v, unsigned long L)
{
  v->next_index = 0;
  v->cap = BUF_SIZE < L ? BUF_SIZE : L;
  v->vec = (unsigned char *)malloc(sizeof(unsigned char) * v->cap);
  memset(v->vec, 0, v->cap);
}

unsigned long next_index(index_vec_t v)
{
  return v->next_index;
}

// return 1(true) if index in a non revocation index
// return 0(flase) otherwise
int non_revokation_index_p(index_vec_t v, unsigned long index)
{
  unsigned long byte_offset = index / 8;
  unsigned long bit_offset  = index % 8;
  
  return (v->vec[byte_offset] >> bit_offset) & 0x1;
}

// return 0 on success
// reutrn 1 otherwise
void assign_index(index_vec_t v, unsigned long index, unsigned long L)
{
  // assert index < L
  if (v->cap * 8 < index + 1) {
    extend_capacity(v, index, L);
  }
  
  // add index into V
  unsigned long byte_offset = index / 8;
  unsigned long bit_offset  = index % 8;
  
  v->vec[byte_offset] |= 0x1 << bit_offset;
  return 0;
}

void extend_capacity(index_vec_t v, unsigned long index, unsigned long L)
{
  // assert index < L
  // (1) cap = index / 8 + 1
  // (2) cap = cap * 2 + 1
  // (1) + (2) makes:
  unsigned long cap = (index / 4) + 3;
  cap = cap < L ? cap : L;
  unsigned char *vec = (unsigned char *)malloc(sizeof(unsigned char) * cap);
  memcpy(vec, v->vec, v->cap);
  memset(vec + v->cap, 0, cap - v->cap);

  v->cap = cap;
  free(v->vec);
  v->vec = vec;
}
