#ifndef __IDEMIX_WITNESS_H__
#define __IDEMIX_WITNESS_H__

#include <pbc/pbc.h>
#include "idemix_bitmap.h"

// a witness belongs to an accmulator
// an accumulator has many witnesses

struct witness_s {
  element_t sigma_i; // in G2
  element_t u_i;     // in G2
  element_t g_i;     // in G1
  element_t w;       // in G2
  bitmap_t V;
};

typedef struct witness_s *witness_ptr;
typedef struct witness_s witness_t[1];

void witness_init(witness_t wit, pairing_t pairing);
void witness_clear(witness_t);
void witness_set(witness_t dst, witness_t src);

#endif // __IDEMIX_WITNESS_H__
