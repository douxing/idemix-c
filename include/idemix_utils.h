#ifndef __IDEMIX_UTILS_H__
#define __IDEMIX_UTILS_H__

#include <pbc/pbc.h>
#include "sm3.h"

void sm3_mpzs(mpz_ptr dest, mpz_ptr n, ...);

void decompose_to_4_squares(mpz_t output[4], mpz_t input);

#endif
