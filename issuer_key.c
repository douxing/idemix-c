#include "idemix_issuer_key.h"
#include "idemix_random.h"
#include <assert.h>

void issuer_keys_fill_R(issuer_sk_t sk,
			issuer_pk_t pk,
			const unsigned long L)
{
  mpz_t two, n_apos;
  mpz_inits(two, n_apos, NULL);
  mpz_set_ui(two, 2);

  mpz_mul(n_apos, sk->p_apos, sk->q_apos); // n' = p'q'
  // n = pq (should be at least 2049 bits > 2048bits)
  mpz_mul(pk->n, sk->p, sk->q);

  // 2. A random quadratic residue S modulo n
  random_num_exact_bits(pk->S, 1024);
  mpz_mul(pk->S, pk->S, pk->S);
  assert(mpz_sizeinbase(pk->S, 2) <= 2048);
  assert(mpz_sizeinbase(pk->S, 2) >= 2047);

  // 3. Random xZ, xR1, ..., xRl in range [2, p'q' - 1]
  // init temporary variables
  // set sk->xZ and pk->Z
  random_range(sk->xZ, two, n_apos);
  mpz_powm(pk->Z, pk->S, sk->xZ, pk->n);

  // set xRi and Ri, formular (1) in paper
  sk->xR_c = pk->R_c = L;
  sk->xR_v = (mpz_ptr)malloc(sizeof(mpz_t) * L);
  pk->R_v  = (mpz_ptr)malloc(sizeof(mpz_t) * L);

  for (unsigned long i = 0; i < L; ++i) {
    mpz_inits(sk->xR_v + i, pk->R_v + i, NULL);
    random_range(sk->xR_v + i, two, n_apos);
    mpz_powm(pk->R_v + i, pk->S, sk->xR_v + i, pk->n);
  }

  mpz_clears(two, n_apos, NULL);
}

void issuer_keys_init_random(issuer_sk_t sk,
			     issuer_pk_t pk,
			     const unsigned long L)
{
  mpz_inits(pk->n, pk->S, pk->Z, NULL);
  mpz_inits(sk->p_apos, sk->q_apos, sk->p, sk->q, sk->xZ, NULL);

  // 1. Random 1024-bit primes p',q'
  // such thatp = 2p'+ 1 and q = 2q'+ 1 are primes too.
  // Then compute n = pq.
  // generate p' and p
  do {
    random_prime_exact_bits(sk->p_apos, 1024);
    mpz_mul_ui(sk->p, sk->p_apos, 2);
    mpz_add_ui(sk->p, sk->p, 1);
  } while(!mpz_probab_prime_p(sk->p, REPS_VAL));

  // generate q' and q
  do {
    random_prime_exact_bits(sk->q_apos, 1024);
    mpz_mul_ui(sk->q, sk->q_apos, 2);
    mpz_add_ui(sk->q, sk->q, 1);
  } while(!mpz_probab_prime_p(sk->q, REPS_VAL));

  issuer_keys_fill_R(sk, pk, L);
}

void issuer_keys_init_assign(issuer_sk_t sk, // OUTPUT
			     issuer_pk_t pk, // OUTPUT
			     const unsigned long L,
			     const mpz_t p_apos,
			     const mpz_t q_apos)
{
  mpz_inits(pk->n, pk->S, pk->Z, NULL);
  mpz_inits(sk->p_apos, sk->q_apos, sk->p, sk->q, sk->xZ, NULL);

  mpz_set(sk->p_apos, p_apos);
  mpz_mul_ui(sk->p, sk->p_apos, 2);
  mpz_add_ui(sk->p, sk->p, 1);
  mpz_set(sk->q_apos, q_apos);
  mpz_mul_ui(sk->q, sk->q_apos, 2);
  mpz_add_ui(sk->q, sk->q, 1);

  issuer_keys_fill_R(sk, pk, L);
}

void issuer_sk_clear(issuer_sk_t sk)
{
  mpz_clears(sk->p_apos,
	     sk->q_apos,
	     sk->p,
	     sk->q,
	     sk->xZ,
	     NULL);
  for (unsigned long i = 0; i < sk->xR_c; ++i) {
    mpz_clear(sk->xR_v + i);
  }
  free(sk->xR_v);
}

void issuer_pk_clear(issuer_pk_t pk)
{
  mpz_clears(pk->n,
	     pk->S,
	     pk->Z,
	     NULL);
  for (unsigned long i = 0; i < pk->R_c; ++i) {
    mpz_clear(pk->R_v + i);
  }
  free(pk->R_v);
}
