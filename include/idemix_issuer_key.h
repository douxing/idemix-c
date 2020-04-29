#ifndef __IDEMIX_ISSUER_KEY_H__
#define __IDEMIX_ISSUER_KEY_H__

#include <gmp.h>

// Chapter 4

// 4.2 Primary Credential Cryptographic Setup
struct issuer_secret_key_s {
  mpz_t p_apos;
  mpz_t q_apos;
  mpz_t p;
  mpz_t q;
  mpz_t xZ;
  unsigned long xR_c;
  mpz_ptr xR_v;
};
typedef struct issuer_secret_key_s *issuer_sk_ptr;
typedef struct issuer_secret_key_s issuer_sk_t[1];

struct issuer_public_key_s {
  mpz_t n;
  mpz_t S;
  mpz_t Z;
  unsigned long R_c;
  mpz_ptr R_v;
};
typedef struct issuer_public_key_s *issuer_pk_ptr;
typedef struct issuer_public_key_s issuer_pk_t[1];

// pk, sk: to be initialized keys
void issuer_keys_init_random(issuer_sk_t sk,
			     issuer_pk_t pk,
			     const unsigned long L);
void issuer_keys_init_assign(issuer_sk_t sk,
			     issuer_pk_t pk,
			     const unsigned long L,
			     const mpz_t p_apos,
			     const mpz_t q_apos);
void issuer_sk_clear(issuer_sk_t sk);
void issuer_pk_clear(issuer_pk_t pk);

#endif // __IDEMIX_ISSUER_KEY_H__
