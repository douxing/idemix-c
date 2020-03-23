#ifndef __IDEMIX_NONREV_CREDENTIAL_SUBPROOF_TUPLE_C_H__
#define __IDEMIX_NONREV_CREDENTIAL_SUBPROOF_TUPLE_C_H__

#include <pbc/pbc.h>

#include "idemix_mpz_vec.h"
#include "idemix_nonrev_key.h"
#include "idemix_nonrev_credential.h"
#include "idemix_nonrev_credential_subproof_auxiliary.h"
#include "idemix_accumulator.h"

// 7.2 2. Create empty sets C
// C is divided to many parts
// related to each Non-revocation credential proof,
// primary credential proof and predicate proof
// we should add these c tuples into the "big C"
// very carefully, with the right order
struct nonrev_credential_subproof_tuple_c_s {
  // page 7 Eq. (22)~(25), will be added to C
  element_t E; // in G1
  element_t D; // in G1
  element_t A; // in G1
  element_t G; // in G1
  element_t W; // in G2
  element_t S; // in G2
  element_t U; // in G2
};
typedef struct nonrev_credential_subproof_tuple_c_s \
               *nonrev_credential_subproof_tuple_c_ptr;
typedef struct nonrev_credential_subproof_tuple_c_s \
               nonrev_credential_subproof_tuple_c_t[1];

void nonrev_credential_subproof_tuple_c_init
(nonrev_credential_subproof_tuple_c_t C,
 pairing_t pairing);

void nonrev_credential_subproof_tuple_c_clear
(nonrev_credential_subproof_tuple_c_t C);

void nonrev_credential_subproof_tuple_c_assign
(nonrev_credential_subproof_tuple_c_t C,
 nonrev_pk_t pk,
 nonrev_credential_t nrc,
 nonrev_credential_subproof_auxiliary_t nrcspa,
 accumulator_t acc);

void nonrev_credential_subproof_tuple_c_into_vec
(mpz_vec_t v,
 nonrev_credential_subproof_tuple_c_t C);

#endif // __IDEMIX_NONREV_CREDENTIAL_SUBPROOF_TUPLE_C_H__
