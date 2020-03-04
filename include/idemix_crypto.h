#ifndef __IDEMIX_CRYPTO_H__
#define __IDEMIX_CRYPTO_H__

#include <pbc/pbc.h>

// Chapter 4

// 4.2 Primary Credential Cryptographic Setup
struct issuer_seckey_s {
  mpz_t p_apos;
  mpz_t q_apos;
  mpz_t p;
  mpz_t q;
  mpz_t xZ;
  unsigned long xR_c;
  mpz_t *xR_v;
};
typedef struct issuer_seckey_s *iss_sk_ptr;
typedef struct issuer_seckey_s iss_sk_t[1];

struct issuer_pubkey_s {
  mpz_t n;
  mpz_t S;
  mpz_t Z;
  unsigned long R_c;
  mpz_t *R_v;
};
typedef struct issuer_pubkey_s *iss_pk_ptr;
typedef struct issuer_pubkey_s iss_pk_t[1];

// pk, sk: to be initialized keys
void primary_crypto_init(iss_sk_t sk,
			 iss_pk_t pk,
			 const unsigned long L);

// TODO: 4.3 Optional: Setup Correctness Proof

// 4.4 Non-revocation Credential Cryptographic Setup
struct non_revok_seckey_s {
  element_t sk; // in Zr
  element_t x;  // in Zr
};
typedef struct non_revok_seckey_s *nr_sk_ptr;
typedef struct non_revok_seckey_s nr_sk_t[1];

struct non_revok_pubkey_s {
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
typedef struct non_revok_pubkey_s *nr_pk_ptr;
typedef struct non_revok_pubkey_s nr_pk_t[1];

// pk, sk : to be initialized element
// pairing: pairing parameter
// g      : the generator of G1
// g_apos : the generator of G2
void non_revok_crypto_init(nr_sk_t sk, // OUTPUT
			   nr_pk_t pk, // OUTPUT
			   pairing_t pairing,
			   element_t g,
			   element_t _g_apos);

// 4.4.1 New Accumulator Setup:

#define INDEX_VEC_INITIAL_CAPACITY 1024

struct index_vec_s {
  unsigned long next_index; // highest index + 1, initially 0
  unsigned long cap;        // = length of vec
  unsigned char *vec;       // bitmap of the index
};
typedef struct index_vec_s *index_vec_ptr;
typedef struct index_vec_s index_vec_t[1];

void index_vec_init(index_vec_t v);
unsigned long next_index(const index_vec_t v);
int has_index(const index_vec_t v,  const unsigned long index);
void set_index(index_vec_t v, const unsigned long index);
void unset_index(index_vec_t v, const unsigned long index);
void index_vec_clear(index_vec_t v);
void index_vec_clone(index_vec_t dst, index_vec_t src);

struct accumulator_s {
  unsigned long L;
  element_t g;      // generator of G1
  element_t g_apos; // generator of G1
  element_t *g1_v;  // in G1, total length: 2L, g1_v[L] = 1
  element_t *g2_v;  // in G2, total length: 2L, g2_v[L] = 1
  element_t z;      // in GT

  element_t acc;    // accumulator itself, in G2, initialized to one
  index_vec_t V;    // container for the index
 };
typedef struct accumulator_s *accumulator_ptr;
typedef struct accumulator_s accumulator_t[1];

struct accumulator_sk_s {
  element_t gamma; // in Zr
};
typedef struct accumulator_sk_s *accum_sk_ptr;
typedef struct accumulator_sk_s accum_sk_t[1];

struct accumulator_pk_s {
  element_t z; // in GT
};
typedef struct accumulator_pk_s *accum_pk_ptr;
typedef struct accumulator_pk_s accum_pk_t[1];

void accumulator_init(accumulator_t acc, // OUT
		      accum_sk_t sk,
		      accum_pk_t pk,
		      pairing_t pairing,
		      unsigned long L,
		      element_t g,
		      element_t _g_apos);

void accumulator_clear(accumulator_t acc);
void accumulator_sk_clear(accum_sk_t sk);
void accumulator_pk_clear(accum_pk_t pk);

// end of 4.4.1
// end of 4.4
// end of Chapter 4

// Chapter 5:

// a witness belongs to an accmulator
// an accumulator has many witnesses

struct witness_s {
  element_t sigma_i; // in G2
  element_t u_i;     // in G2
  element_t g_i;     // in G1
  element_t w;       // in G2
  index_vec_t V;
};

typedef struct witness_s *witness_ptr;
typedef struct witness_s witness_t[1];

void witness_init(witness_t wit, pairing_t pairing);
void witness_clear(witness_t);


// page 5 formular (16)
void compute_w(element_t w, // OUT
	       accumulator_t acc,
	       const unsigned long i);

// end of Chapter 5

// Chapter 7

struct mpz_vec_s {
  unsigned long mpz_c;
  mpz_t *mpz_v;
};
typedef struct mpz_vec_s *mpz_vec_ptr;
typedef struct mpz_vec_s mpz_vec_t[1];

void mpz_vec_init(mpz_vec_t v, unsigned long cap);

// end of Chapter 7

#endif
