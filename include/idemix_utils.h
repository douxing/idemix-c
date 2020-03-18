#ifndef __IDEMIX_UTILS_H__
#define __IDEMIX_UTILS_H__

#include <pbc/pbc.h>
#include "sm3.h"
#include "decompose.h"
#include "idemix_mpz_vec.h"

void sm3_mpzs(mpz_t dest, mpz_ptr n, ...);

// 7.2.1 Hashing
void sm3_TCn(mpz_ptr dst, mpz_vec_t T, mpz_vec_t C, mpz_t n);

#endif // __IDEMIX_UTILD_H__
