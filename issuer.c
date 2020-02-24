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

  // n = pq (should be at least 2049bits > 2048bits)
  mpz_mul(pk->n, sk->p, sk->q);

  // 2. A random quadratic residue S modulo n
  random_n_bits(x, 1025);
  mpz_powm_ui(pk->S, x, 2, pk->n); // no need to mod, in fact
  // no need to check mpz_sizeinbase(pk->S, 2) < 2048);

  // 3. Random x_Z, x_R1, ..., x_Rl in range [2, p'q' - 1]
  // set sk->x_Z and pk->Z
  mpz_set_ui(min, 2);
  mpz_mul(max, sk->p_apos, sk->q_apos);
  random_range(sk->x_Z, min, max);
  mpz_powm(pk->Z, pk->S, sk->x_Z, pk->n);
  sk->x_R_c = 0;
  sk->x_R_v = NULL;
  pk->R_c = 0;
  pk->R_v = NULL;

  // set sk->x_R_v and pk->R_v, update sk->x_R_c and pk->R_c
  issuer_extend_keys(l, min, max, pk, sk);
}

// a function to endable extension of pk and sk
void issuer_extend_keys(unsigned long l_inc,
			mpz_t min, mpz_t max,
			issuer_pk_t pk, issuer_sk_t sk)
{
  // TODO: assert pk->R_c == sk->x_R_c;
  if (l_inc == 0) {
    return;
  }

  // handle first element
  issuer_sk_x_ptr sk_x = (issuer_sk_x_ptr)malloc(sizeof(struct issuer_sk_x_s));
  issuer_pk_R_ptr pk_R = (issuer_pk_R_ptr)malloc(sizeof(struct issuer_pk_R_s));
  random_range(sk_x->x, min, max);
  mpz_powm(pk_R->R, pk->S, sk_x->x, pk->n);

  issuer_sk_x_ptr sk_x_head = sk_x;
  issuer_pk_R_ptr pk_R_head = pk_R;
  issuer_sk_x_ptr sk_x_tail = sk_x;
  issuer_pk_R_ptr pk_R_tail = pk_R;

  // handle elements in range [1:]
  for (unsigned long i = 1; i < l_inc; ++i) {
    issuer_sk_x_ptr sk_x = malloc(sizeof(struct issuer_sk_x_s));
    issuer_pk_R_ptr pk_R = malloc(sizeof(struct issuer_pk_R_s));
    random_range(sk_x->x, min, max);
    mpz_powm(pk_R->R, pk->S, sk_x->x, pk->n);

    sk_x_tail->next = sk_x;
    pk_R_tail->next = pk_R;
    sk_x_tail = sk_x;
    pk_R_tail = pk_R;
  }

  sk_x_tail->next = NULL;
  pk_R_tail->next = NULL;

  // append to the current list
  if (sk->x_R_c == 0) {
    // assert sk->x_R_v == NULL, pk->R_v == NULL
    sk->x_R_v = sk_x_head;
    pk->R_v = pk_R_head;
  } else {
    // assert sk->x_R_v != NULL, pk->R_v != NULL
    sk_x = sk->x_R_v;
    pk_R = pk->R_v;
    for (unsigned long i = 1; i < sk->x_R_c; ++i) {
      sk_x = sk_x->next;
      pk_R = pk_R->next;
    }
    sk_x->next = sk_x_head;
    pk_R->next = pk_R_head;
  }

  sk->x_R_c += l_inc;
  pk->R_c += l_inc;
}

// section 4.4 Non-revokation Credential Cryptographic setup
void revok_keys_setup(pairing_t pairing, element_t g, revok_pk_t pk, revok_sk_t sk)
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
    
}


