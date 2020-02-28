#ifndef __IDEMIX_ACCUMULATOR_H__
#define __IDEMIX_ACCUMULATOR_H__

#include <pbc/pbc.h>

struct index_vec_s {
  unsigned long next_index; // highest index + 1, initially 0
  unsigned long cap;  // = length of vec
  unsigned char *vec; // bitmap of the index
};
typedef struct index_vec_s index_vec_t[1];

struct accumulator_pk_s {
  element_t z; // in Gt
};
typedef struct accumulator_pk_s *accum_pk_ptr;
typedef struct accumulator_pk_s accum_pk_t[1];

struct accumulator_sk_s {
  element_t gamma; // in Zr
};
typedef struct accumulator_sk_s *accum_sk_ptr;
typedef struct accumulator_sk_s accum_sk_t[1];

struct accumulator_s {
  unsigned long L;
  element_t *g1_v; // in G1, total length: 2L, g1_v[L] = g (generator of G1)
  element_t *g2_v; // in G2, total length: 2L, g2_v[L] = g_apos (generator of G2)
  element_t z;     // in GT
  element_t acc;   // accumulator itself, in G2, initialized to one
  index_vec_t V;   // container for the index
};
typedef struct accumulator_s *accumulator_ptr;
typedef struct accumulator_s accumulator_t[1];

// section 4.4.1 New Accumulator Setup
void accumulator_setup(pairing_t pairing, unsigned long L,
		       element_t g, element_t g_apos,
		       accum_pk_t pk, accum_sk_t sk,
		       accumulator_t acc);

// page 5 formular (16) omega
void compute_omega(element_t omega, accumulator_t acc, unsigned long i);

void init_index_vec(index_vec_t v, unsigned long L);
unsigned long next_index(index_vec_t v);
int  non_revokation_index_p(index_vec_t v, unsigned long index);
void assign_index(index_vec_t v, unsigned long index, unsigned long L);
void extend_capacity(index_vec_t v, unsigned long index, unsigned long L);

#endif
