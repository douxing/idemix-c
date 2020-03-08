#ifndef __IDEMIX_UTILS_H__
#define __IDEMIX_UTILS_H__

#include <pbc/pbc.h>
#include "sm3.h"

void sm3_mpzs(mpz_ptr dest, mpz_ptr n, ...);

void decompose_to_4_squares(mpz_t delta,
			    mpz_t u1,  // OUT
			    mpz_t u2,  // OUT
			    mpz_t u3,  // OUT
			    mpz_t u4); // OUT

#endif
