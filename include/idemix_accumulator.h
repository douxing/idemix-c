#ifndef __IDEMIX_ACCUMULATOR_H__
#define __IDEMIX_ACCUMULATOR_H__

#include <pbc/pbc.h>

#include "idemix_index_vec.h"

struct accumulator_s {
  unsigned long L;
  element_t g;      // generator of G1
  element_t g_apos; // generator of G2

  element_t *g1_v;  // in G1, total length: 2L, g1_v[L] = 1
  element_t *g2_v;  // in G2, total length: 2L, g2_v[L] = 1

  index_vec_t V;    // container for the index
  element_t acc;    // accumulator itself, in G2, initialized to one
};
typedef struct accumulator_s *accumulator_ptr;
typedef struct accumulator_s accumulator_t[1];

void accumulator_clear(accumulator_t acc);

struct accumulator_sk_s {
  element_t gamma; // in Zr
};
typedef struct accumulator_sk_s *accum_sk_ptr;
typedef struct accumulator_sk_s accum_sk_t[1];

void accumulator_sk_clear(accum_sk_t sk);

struct accumulator_pk_s {
  element_t z; // in GT
};
typedef struct accumulator_pk_s *accum_pk_ptr;
typedef struct accumulator_pk_s accum_pk_t[1];

void accumulator_pk_clear(accum_pk_t pk);

void accumulator_init(accumulator_t acc, // OUT
		      accum_sk_t sk,     // OUT
		      accum_pk_t pk,     // OUT
		      pairing_t pairing,
		      unsigned long L,
		      element_t g,
		      element_t _g_apos);

#endif // __IDEMIX_ACCUMULATOR_H__
