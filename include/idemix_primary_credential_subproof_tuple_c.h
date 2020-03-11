#ifndef __IDEMIX_PRIMARY_CREDENTIAL_SUBPROOF_TUPLE_C_H__
#define __IDEMIX_PRIMARY_CREDENTIAL_SUBPROOF_TUPLE_C_H__

#include <pbc/pbc.h>
#include "idemix_mpz_vec.h"
#include "idemix_issuer_key.h"
#include "idemix_primary_credential.h"
#include "idemix_primary_credential_subproof_auxiliary.h"


// 7.2 2. Create empty sets C
// C is divided to many parts
// related to each Non-revocation credential proof,
// primary credential proof and predicate proof
// we should add these c tuples into the "big C"
// very carefully, with the right order

struct primary_credential_subproof_tuple_c_s {
  mpz_t A_apos; // Eq. (33) A' = AS^r (mod n)
};
typedef struct primary_credential_subproof_tuple_c_s \
               *primary_credential_subproof_tuple_c_ptr;
typedef struct primary_credential_subproof_tuple_c_s \
               primary_credential_subproof_tuple_c_t[1];

void primary_credential_subproof_tuple_c_init
(primary_credential_subproof_tuple_c_t C);

void primary_credential_subproof_tuple_c_clear
(primary_credential_subproof_tuple_c_t C);

void primary_credential_subproof_tuple_c_assign
(primary_credential_subproof_tuple_c_t C,
 issuer_pk_t pk,
 primary_credential_t pc,
 primary_credential_subproof_auxiliary_t pcspa);

void primary_credential_subproof_tuple_c_into_vec
(mpz_vec_t v, // OUT
 primary_credential_subproof_tuple_c_t C);

#endif // __IDEMIX_PRIMARY_CREDENTIAL_SUBPROOF_TUPLE_C_H__
