#ifndef __IDEMIX_CRYPTO_H__
#define __IDEMIX_CRYPTO_H__

#include <pbc/pbc.h>
#include "idemix_accumulator.h"

// Chapter 4

// 4.2 Primary Credential Cryptographic Setup
struct issuer_secret_key_s {
  mpz_t p_apos;
  mpz_t q_apos;
  mpz_t p;
  mpz_t q;
  mpz_t xZ;
  unsigned long xR_c;
  mpz_t *xR_v;
};
typedef struct issuer_secret_key_s *issuer_sk_ptr;
typedef struct issuer_secret_key_s issuer_sk_t[1];

struct issuer_public_key_s {
  mpz_t n;
  mpz_t S;
  mpz_t Z;
  unsigned long R_c;
  mpz_t *R_v;
};
typedef struct issuer_public_key_s *issuer_pk_ptr;
typedef struct issuer_public_key_s issuer_pk_t[1];

// pk, sk: to be initialized keys
void primary_crypto_init(issuer_sk_t sk,
			 issuer_pk_t pk,
			 const unsigned long L);

// TODO: 4.3 Optional: Setup Correctness Proof

// 4.4 Non-revocation Credential Cryptographic Setup
struct non_revocation_secret_key_s {
  element_t sk; // in Zr
  element_t x;  // in Zr
};
typedef struct non_revocation_secret_key_s *nonrev_sk_ptr;
typedef struct non_revocation_secret_key_s nonrev_sk_t[1];

struct nonrev_public_key_s {
  // in G1
  element_t h;
  element_t h0;
  element_t h1;
  element_t h2;
  element_t h_tilde;

  // in G2
  element_t u;
  element_t h_caret;

  // in Zr
  element_t pk;
  element_t y;
};
typedef struct nonrev_public_key_s *nonrev_pk_ptr;
typedef struct nonrev_public_key_s nonrev_pk_t[1];

// pk, sk : to be initialized element
// pairing: pairing parameter
// g      : the generator of G1
// g_apos : the generator of G2
void nonrev_crypto_init(nonrev_sk_t sk, // OUTPUT
			nonrev_pk_t pk, // OUTPUT
			pairing_t pairing,
			element_t g,
			element_t _g_apos);

// 4.4.1 New Accumulator Setup:
// end of 4.4.1
// end of 4.4
// end of Chapter 4

// Chapter 5:

// page 5 formular (16)
void compute_w(element_t w, // OUT
	       accumulator_t acc,
	       const unsigned long i);

// end of Chapter 5

#endif
