#include "idemix_utils.h"
#include "idemix_crypto.h"

#include <string.h>

// Chapter 4:

void primary_crypto_init(iss_sk_t sk, // OUTPUT
			 iss_pk_t pk, // OUTPUT
			 const unsigned long L)
{
  mpz_inits(pk->n, pk->S, pk->Z);
  mpz_inits(sk->p_apos, sk->q_apos, sk->p, sk->q);

  // 1. Random 1024-bit primes p',q'
  // such thatp = 2p'+ 1 and q = 2q'+ 1 are primes too.
  // Then compute n = pq.
  // generate p' and p
  do {
    random_prime_exact_bits(sk->p_apos, 1024);
    mpz_mul_ui(sk->p, sk->p_apos, 2);
    mpz_add_ui(sk->p, sk->p, 1);
  } while(mpz_probab_prime_p(sk->p, REPS_VAL));

  // generate q' and q
  do {
    random_prime_exact_bits(sk->q_apos, 1024);
    mpz_mul_ui(sk->q, sk->q_apos, 2);
    mpz_add_ui(sk->q, sk->q, 1);
  } while(mpz_probab_prime_p(sk->q, REPS_VAL));

  // n = pq (should be at least 2049 bits > 2048bits)
  mpz_mul(pk->n, sk->p, sk->q);
    
  // 2. A random quadratic residue S modulo n
  random_num_exact_bits(pk->S, 1024);
  mpz_powm_ui(pk->S, pk->S, 2, pk->n); // no need to mod, at most 2048 bits
  // no need to check mpz_sizeinbase(pk->S, 2) < 2048);

  // 3. Random xZ, xR1, ..., xRl in range [2, p'q' - 1]
  // init temporary variables
  mpz_t two, n_apos;
  mpz_inits(two, n_apos);
  mpz_set_ui(two, 2);
  mpz_mul(n_apos, sk->p_apos, sk->q_apos); // n' = p'q'

  // set sk->xZ and pk->Z
  random_range(sk->xZ, two, n_apos);
  mpz_powm(pk->Z, pk->S, sk->xZ, pk->n);

  // set xRi and Ri, formular (1) in paper
  sk->xR_c = pk->R_c = L;
  sk->xR_v = (mpz_t *)malloc(sizeof(mpz_t) * L);
  pk->R_v  = (mpz_t *)malloc(sizeof(mpz_t) * L);

  for (unsigned long i = 0; i < L; ++i) {
    mpz_inits(sk->xR_v[i], pk->R_v[i]);
    random_range(sk->xR_v[i], two, n_apos);
    mpz_powm(pk->R_v[i], pk->S, sk->xR_v[i], pk->n);
  }

  mpz_clears(two, n_apos);
}

// section 4.4 Non-revokation Credential Cryptographic setup
// pk, sk : to be initialized element
// pairing: pairing parameter
// g      : the generator of G1
// g_apos : the generator of G2
void non_revok_crypto_init(nr_sk_t sk, // OUTPUT
			   nr_pk_t pk, // OUTPUT
			   pairing_t pairing,
			   element_t g,
			   element_t _g_apos)
{
  (void)_g_apos;

  // init secret key
  element_init_Zr(sk->x, pairing);
  element_init_Zr(sk->sk, pairing);
  element_random(sk->x);
  element_random(sk->sk);

  // init public key
  element_init_G1(pk->h, pairing);
  element_init_G1(pk->h0, pairing);
  element_init_G1(pk->h1, pairing);
  element_init_G1(pk->h2, pairing);
  element_init_G1(pk->h_tilde, pairing);
  element_random(pk->h);
  element_random(pk->h0);
  element_random(pk->h1);
  element_random(pk->h2);
  element_random(pk->h_tilde);

  element_init_G2(pk->u, pairing);
  element_init_G2(pk->h_caret, pairing);
  element_random(pk->u);
  element_random(pk->h_caret);

  element_init_G1(pk->pk, pairing);
  element_init_G2(pk->y, pairing);
  element_pow_zn(pk->pk, g, sk->sk);
  element_pow_zn(pk->y, pk->h_caret, sk->x);
}

// 4.4.1 New Accumulator Setup:

void index_vec_init(index_vec_t v)
{
  v->next_index = 0;
  v->cap = INDEX_VEC_INITIAL_CAPACITY / 8;
  v->vec = (unsigned char *)malloc(sizeof(unsigned char) * v->cap);
  memset(v->vec, 0, v->cap);
}

unsigned long next_index(const index_vec_t v)
{
  return v->next_index;
}

// return 1(true) if the vector contains index
// return 0(flase) otherwise
int has_index(const index_vec_t v, const unsigned long i)
{
  unsigned long byte_offset = i / 8;
  unsigned long bit_offset  = i % 8;
  
  return (v->vec[byte_offset] >> bit_offset) & 0x1;
}

void set_index(index_vec_t v, const unsigned long i)
{
  unsigned long cap = i / 8 + 1;
  if (v->cap < cap) {
    // allocate more memory
    cap = cap * 2 + 1;
    unsigned char *vec = (unsigned char *)malloc(sizeof(unsigned char) * cap);
    memcpy(vec, v->vec, v->cap);
    memset(vec + v->cap, 0, cap - v->cap);
    v->cap = cap;
    v->vec = vec;
  }

  unsigned long byte_offset = i / 8;
  unsigned long bit_offset  = i % 8;
  
  v->vec[byte_offset] = 1 << bit_offset;
}

void index_vec_clear(index_vec_t v)
{
  free(v->vec);
}



void accumulator_init(accumulator_t acc, // OUTPUT
		      accum_sk_t sk,     // OUTPUT
		      accum_pk_t pk,     // OUTPUT
		      pairing_t pairing,
		      unsigned long L,
		      element_t g,
		      element_t g_apos)
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
  index_vec_init(acc->V);
  element_init_G2(acc->acc, pairing);

  mpz_clear(L_plus_one);
  element_clear(gamma_pow_L_plus_one);
}

void accumulator_clear(accumulator_t acc)
{
  for (unsigned i = 0; i < acc->L * 2; ++i) {
    element_clear(acc->g1_v[i]);
    element_clear(acc->g2_v[i]);
  }
  free(acc->g1_v);
  free(acc->g2_v);

  element_clear(acc->z);
  element_clear(acc->acc);

  index_vec_clear(acc->V);
}

void accumulator_sk_clear(accum_sk_t sk)
{
  element_clear(sk->gamma);
}

void accumulator_pk_clear(accum_pk_t pk)
{
  element_clear(pk->z);
}

// end of 4.4.1
// end of 4.4
// end of Chapter 4

// Chapter 5:

void witness_init(witness_t wit, // OUTPUT
		  pairing_t pairing)
{
  element_init_G2(wit->sigma_i, pairing);
  element_init_G2(wit->u_i, pairing);
  element_init_G1(wit->g_i, pairing);
  element_init_G2(wit->omega, pairing);
  index_vec_init(wit->V);
}

void compute_omega(element_t omega, // OUTPUT
		   const accumulator_t acc,
		   const unsigned long i)
{
  element_set1(omega);
  for (unsigned long j = 0; j < next_index(acc->V); ++j) {
    if (i != j) {
      unsigned long sub = acc->L + 1 - j + i;
      element_mul(omega, omega, acc->g2_v[sub]);
    }
  }
}

// end of Chapter 5

// Chapter 7:

/* void compute_new_omega(element_t omega, // OUTPUT */
/* 		       accumulator_t acc, */
/* 		       unsigned long i, */
/* 		       witness_t wit, */
/* 		       index_vec_t new_V) */
/* { */
/*   element_set(omega, wit->omega); */
/*   // TODO update witness */
/* } */

// end of Chapter 7
