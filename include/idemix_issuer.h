#ifndef __IDEMIX_ISSUER_H__
#define __IDEMIX_ISSUER_H__

#include <pbc/pbc.h>

// Chapter 4:
struct issuer_pk_s {
  mpz_t n;  
  mpz_t S;
  mpz_t Z;
  unsigned long R_c;
  mpz_t *R_v;
};
typedef struct issuer_pk_s *issuer_pk_ptr;
typedef struct issuer_pk_s issuer_pk_t[1];

struct issuer_sk_s {
  mpz_t p_apos;
  mpz_t q_apos;
  mpz_t p;
  mpz_t q;
  mpz_t xZ;
  unsigned long xR_c;
  mpz_t *xR_v;
};
typedef struct issuer_sk_s *issuer_sk_ptr;
typedef struct issuer_sk_s issuer_sk_t[1];

struct revok_pk_s {
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
typedef struct revok_pk_s *revok_pk_ptr;
typedef struct revok_pk_s revok_pk_t[1];

struct revok_sk_s {
  element_t sk;
  element_t x;
};
typedef struct revok_sk_s *revok_sk_ptr;
typedef struct revok_sk_s revok_sk_t[1];

struct accum_pk_s {
  element_t z; // in Gt
};
typedef struct accum_pk_s *accum_pk_ptr;
typedef struct accum_pk_s accum_pk_t[1];

struct accum_sk_s {
  element_t gamma; // in Zr
};
typedef struct accum_sk_s *accum_sk_ptr;
typedef struct accum_sk_s accum_sk_t[1];

struct accumulator_s {
  unsigned long L;
  element_t *g1_v; // in G1, total length: 2L, g1_v[L] = g (generator of G1)
  element_t *g2_v; // in G2, total length: 2L, g2_v[L] = g_apos (generator of G2)
  element_t z;     // in GT
  element_t acc;   // accumulator itself, in G2, initialized to one
  // V, how to init?
};
typedef struct accumulator_s *accumulator_ptr;
typedef struct accumulator_s accumulator_t[1];

// section 4.2 Primary Credential Cryptographic setup
// attr_c: supported attribute number
// pk, sk: un-setup keys
void issuer_keys_setup(unsigned long L, issuer_pk_t pk, issuer_sk_t sk);

// TODO: section 4.3

// section 4.4 Non-revokation Credential Cryptographic setup
void revok_keys_setup(pairing_t pairing,
		      element_t g, element_t g_apos,
		      revok_pk_t pk, revok_sk_t sk);

// section 4.4.1 New Accumulator Setup
void accum_setup(pairing_t pairing, unsigned long L,
		 element_t g, element_t g_apos,
		 accum_pk_t pk, accum_sk_t sk, accumulator_t acc);

// end of Chapter 4

// chapter 5:



// end of Chapter 5

void init_CS(int attrc, char *attrv[], issuer_pk_t);


#endif
