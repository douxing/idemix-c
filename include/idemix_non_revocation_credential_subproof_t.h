#ifndef __IDEMIX_NON_REVOCATION_CREDENTIAL_SUBPROOF_TUPLE_T_H__
#define __IDEMIX_NON_REVOCATION_CREDENTIAL_SUBPROOF_TUPLE_T_H__

#include <pbc/pbc.h>

#include "idemix_mpz_vec.h"
#include "idemix_accumulator.h"
#include "idemix_non_revocation_key.h"
#include "idemix_non_revocation_credential.h"
#include "idemix_non_revocation_credential_subproof_auxiliary.h"
#include "idemix_non_revocation_credential_subproof_tuple_c.h"

// no need for tuple

void nonrev_credential_subproof_t_into_vec
(mpz_vec_t T,
 pairing_t pairing,
 nonrev_pk_t pk,
 accumulator_t acc,
 nonrev_credential_subproof_auxiliary_t nrcspa,
 nonrev_credential_subproof_tuple_c_t C);

#endif // __IDEMIX_NON_REVOCATION_CREDENTIAL_SUBPROOF_TUPLE_T_H__
