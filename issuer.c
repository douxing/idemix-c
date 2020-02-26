#include <stdlib.h>
#include <gmp.h>
#include "idemix_utils.h"
#include "idemix_issuer.h"
#include "idemix_holder.h"

// section 4.2 Primary Credential Cryptographic setup
void issuer_keys_setup(unsigned long L, issuer_pk_t pk, issuer_sk_t sk)
{
  mpz_inits(pk->n, pk->S, pk->Z);
  mpz_inits(sk->p_apos, sk->q_apos, sk->p, sk->q);

  // init temporary variables
  mpz_t x, min, max;
  mpz_inits(x, min, max);

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
  random_num_exact_bits(x, 1024);
  mpz_powm_ui(pk->S, x, 2, pk->n); // no need to mod, at most 2048 bits
  // no need to check mpz_sizeinbase(pk->S, 2) < 2048);

  // 3. Random xZ, xR1, ..., xRl in range [2, p'q' - 1]
  // set sk->xZ and pk->Z
  mpz_set_ui(min, 2);
  mpz_mul(max, sk->p_apos, sk->q_apos);
  random_range(sk->xZ, min, max);
  mpz_powm(pk->Z, pk->S, sk->xZ, pk->n);

  // set xRi and Ri, formular (1) in paper
  sk->xR_c = pk->R_c = L;
  sk->xR_v = (mpz_t *)malloc(sizeof(mpz_t) * L);
  pk->R_v  = (mpz_t *)malloc(sizeof(mpz_t) * L);

  for (unsigned long i = 0; i < L; ++i) {
    mpz_inits(sk->xR_v[i], pk->R_v[i]);
    random_range(sk->xR_v[i], min, max);
    mpz_powm(pk->R_v[i], pk->S, sk->xR_v[i], pk->n);
  }
}

// section 4.4 Non-revokation Credential Cryptographic setup
// pairing: pairing parameter 
// g      : the generator of G1
// g_apos : the generator of G2
// pk, sk : to be initialized element
void revok_keys_setup(pairing_t pairing,
		      element_t g, element_t _g_apos,
		      revok_pk_t pk, revok_sk_t sk)
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

// section 4.4.1 New Accumulator Setup
void accum_setup(pairing_t pairing, unsigned long L,
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
  element_init_G2(acc->acc, pairing);
}

// 5.2 Primary Credential Issurance
int issure_primary_credential(issuer_pk_t pk, pre_prim_cred_t ppc,
			      mpz_t n0,
			      accumulator_t acc,
			      unsigned long i, mpz_t H_cop)
{
  // assert index < acc->L

  // Issuer verifies the corretness of Holder's input:
  mpz_t U_caret, temp;
  mpz_inits(U_caret, temp);
  // 1. Compute U_caret
  // page 4 formular (9)
  mpz_invert(U_caret, ppc->U, pk->n);
  mpz_powm(U_caret, U_caret, ppc->c, pk->n);
  mpz_powm(temp, pk->R_v[0], ppc->m1_caret, pk->n);
  mpz_mul(U_caret, U_caret, temp);
  mpz_powm(temp, pk->S, ppc->v_apos_caret, pk->n);
  mpz_mul(U_caret, U_caret, temp);

  // 2. verify c = H(U||U_caret||n0)
  char buf[BUF_SIZE] = { 0 };
  unsigned char c[SM3_DIGEST_LENGTH] = { 0 };
  size_t count;
  sm3_ctx_t ctx;
  sm3_init(&ctx);
  mpz_export(buf, &count, 1, 1, 1, 0, ppc->U);
  sm3_update(&ctx, (void *)buf, count);
  mpz_export(buf, &count, 1, 1, 1, 0, U_caret);
  sm3_update(&ctx, (void *)buf, count);
  mpz_export(buf, &count, 1, 1, 1, 0, n0);
  sm3_update(&ctx, (void *)buf, count);
  sm3_final(&ctx, c);
  memset(&ctx, 0, sizeof(sm3_ctx_t));
  mpz_import(temp, SM3_DIGEST_LENGTH, 1, 1, 1, 0, c); // temp = c
  int res = mpz_cmp(ppc->c, temp);
  if (res != 0) {
    gmp_printf("hash differs, \nc(U) : %Z\nc(U^): %Z\n");
    return -1;
  }

  // 3. Verify the length of v'^, m1^
  // ... ignore ...

  // Issuer prepare the credential:
  // 1. Compute m2 <- H(i||H_cop)
  sm3_init(&ctx);
  mpz_set_ui(temp, i);
  mpz_export(buf, &count, 1, 1, 1, 0, temp);
  sm3_update(&ctx, buf, count);
  mpz_export(buf, &count, 1, 1, 1, 0, H_cop);
  sm3_update(&ctx, buf, count);
  sm3_final(&ctx, c);
  mpz_import(temp, SM3_DIGEST_LENGTH, 1, 1, 1, 0, c); // temp = m2


  return 0;
}
