#include "idemix_random.h"
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

// end of 4.4.1
// end of 4.4
// end of Chapter 4

// Chapter 5:

void compute_w(element_t w, // OUTPUT
	       accumulator_t acc,
	       const unsigned long i)
{
  element_set1(w);
  unsigned long j = bitmap_scan1(acc->V, 0);
  while (j < acc->L) {
    if (j != i) {
      element_mul(w, w, acc->g2_v[acc->L -j + i]);
    }
    
    j = bitmap_scan1(acc->V, j + 1);
  }
}

// end of Chapter 5

// Chapter 7:

// end of Chapter 7
