#ifndef __IDEMIX_PROOFS_H__
#define __IDEMIX_PROOFS_H__

#include <pbc/pbc.h>

#include "idemix_mpz_vec.h"
#include "idemix_accumulator.h"

// Chapter 7

// Use as the container for T and C
// 7.2 - 2 create empty sets T and C

void non_revok_proof
(mpz_vec_t TT,
 mpz_vec_t CC,
 accumulator_t acc
 );

// end of Chapter 7



#endif
