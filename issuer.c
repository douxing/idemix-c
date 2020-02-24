#include <stdlib.h>
#include <gmp.h>
#include "idemix_utils.h"
#include "idemix_issuer.h"

// section 4.2 Primary Credential Cryptographic setup
void issuer_keys_setup(unsigned long l, issuer_pk_t pk, issuer_sk_t sk)
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

  // 3. Random x_Z, x_R1, ..., x_Rl in range [2, p'q' - 1]
  // set sk->x_Z and pk->Z
  mpz_set_ui(min, 2);
  mpz_mul(max, sk->p_apos, sk->q_apos);
  random_range(sk->x_Z, min, max);
  mpz_powm(pk->Z, pk->S, sk->x_Z, pk->n);

  // set x_Ri and Ri
  sk->x_R_c = pk->R_c = l;
  sk->x_R_v = (mpz_t *)malloc(sizeof(mpz_t) * l);
  pk->R_v   = (mpz_t *)malloc(sizeof(mpz_t) * l);

  for (unsigned long i = 0; i < l; ++i) {
    mpz_inits(sk->x_R_v[i], pk->R_v[i]);
    random_range(sk->x_R_v[i], min, max);
    mpz_powm(pk->R_v[i], pk->S, sk->x_R_v[i], pk->n);
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

void accum_setup(accum_pk_t pk, accum_sk_t sk)
{
}
