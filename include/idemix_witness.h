#ifndef __IDEMIX_WITNESS_H__
#define __IDEMIX_WITNESS_H__

#include <pbc/pbc.h>
#include "idemix_index_vec.h"

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

#endif // __IDEMIX_WITNESS_H__
