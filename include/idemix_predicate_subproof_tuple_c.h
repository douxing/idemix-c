#ifndef __IDEMIX_PREDICATE_SUBPROOF_TUPLE_C_H__
#define __IDEMIX_PREDICATE_SUBPROOF_TUPLE_C_H__

#include <pbc/pbc.h>
#include "idemix_predicate_subproof_auxiliary.h"

// 7.2 2. Create empty sets C
// C is divided to many parts
// related to each Non-revocation credential proof,
// primary credential proof and predicate proof
// we should add these c tuples into the "big C"
// very carefully, with the right order
struct predicate_subproof_tuple_c_s {
  mpz_t T[4];    // Eq. (36)
  mpz_t T_delta; // Eq. (37)
};
typedef struct predicate_subproof_tuple_c_s *predicate_subproof_tuple_c_ptr;
typedef struct predicate_subproof_tuple_c_s predicate_subproof_tuple_c_t[1];

void predicate_subproof_tuple_c_init
(predicate_subproof_tuple_c_t C);

void predicate_subproof_tuple_c_clear
(predicate_subproof_tuple_c_t C);

void predicate_subproof_tuple_c_assign
(predicate_subproof_tuple_c_t C,
 issuer_pk_t pk,
 predicate_subproof_auxiliary_t pspa);

#endif // __IDEMIX_PREDICATE_SUBPROOF_TUPLE_C_H__
