#include <gmp.h>
#include "idemix_utils.h"
#include "idemix_issuer.h"

// section 4.2 Primary Credential Cryptographic setup
void issuer_keys_setup(unsigned long attr_c, issuer_pk_t pk, issuer_sk_t sk)
{
  mpz_init(pk->n);
  mpz_init(pk->S);
  mpz_init(pk->Z);
  mpz_init(sk->p_apos);
  mpz_init(sk->q_apos);
  mpz_init(sk->p);
  mpz_init(sk->q);

  // 1. Random 1024-bit primes p′,q′
  // such thatp = 2p′+ 1 and q = 2q′+ 1 are primes too.
  // Then compute n←pq.
  // generate p' and p
  do {
    random_prime(sk->p_apos, 1024);
    mpz_mul_ui(sk->p, sk->p_apos, 2);
    mpz_add_ui(sk->p, sk->p, 1);
  } while(mpz_probab_prime_p(sk->p, REPS_VAL));

  // generate q' and q
  do {
    random_prime(sk->q_apos, 1024);
    mpz_mul_ui(sk->q, sk->q_apos, 2);
    mpz_add_ui(sk->q, sk->q, 1);
  } while(mpz_probab_prime_p(sk->q, REPS_VAL));

  // n = pq
  mpz_mul(pk->n, sk->p, sk->q);

  // 4.2 - 2. A random quadratic residue S modulo n

  // 
  for (unsigned long i = 0; i < attr_c; ++i) {
    
  }
}

// TODO: add a function to endable extension of pk and sk

