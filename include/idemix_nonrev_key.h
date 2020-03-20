#ifndef __IDEMIX_NONREV_KEY_H__
#define __IDEMIX_NONREV_KEY_H__

#include <pbc/pbc.h>
#include "idemix_accumulator.h"

// Chapter 4

// 4.4 Non-revocation Credential Cryptographic Setup
struct nonrev_secret_key_s {
  element_t sk; // in Zr
  element_t x;  // in Zr
};
typedef struct nonrev_secret_key_s *nonrev_sk_ptr;
typedef struct nonrev_secret_key_s nonrev_sk_t[1];

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
void nonrev_keys_init_assign(nonrev_sk_t sk, // OUTPUT
			     nonrev_pk_t pk, // OUTPUT
			     pairing_t pairing,
			     element_t g,
			     element_t _g_apos);

void nonrev_sk_clear(nonrev_sk_t sk);
void nonrev_pk_clear(nonrev_pk_t pk);

// 4.4.1 New Accumulator Setup:
// @see accumulator_t
// end of 4.4.1

// end of 4.4

// end of Chapter 4

#endif // __IDEMIX_NONREV_KEY_H__
