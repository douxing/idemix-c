#ifndef __IDEMIX_UTILS_H__
#define __IDEMIX_UTILS_H__

#include <pbc/pbc.h>
#include "sm3.h"
#include "idemix_mpz_vec.h"

void sm3_mpzs(mpz_t dest, mpz_ptr n, ...);

// 7.2.1 Hashing
void sm3_TCn1(mpz_ptr dst, mpz_vec_t T, mpz_vec_t C, mpz_t n1);

void decompose_to_4_squares(mpz_t u[4], // OUT
			    mpz_t delta);

#endif // __IDEMIX_UTILD_H__
