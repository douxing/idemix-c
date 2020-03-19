#ifndef __IDEMIX_NONREV_CREDENTIAL_SUBPROOF_DUMP_T_H__
#define __IDEMIX_NONREV_CREDENTIAL_SUBPROOF_DUMP_T_H__

#include <pbc/pbc.h>

#include "idemix_mpz_vec.h"
#include "idemix_accumulator.h"
#include "idemix_nonrev_key.h"
#include "idemix_nonrev_credential.h"
#include "idemix_nonrev_credential_subproof_auxiliary.h"
#include "idemix_nonrev_credential_subproof_tuple_c.h"

// no need for tuple

void nonrev_credential_subproof_dump_t
(mpz_vec_t T,
 pairing_t pairing,
 nonrev_pk_t pk,
 accumulator_t acc,
 nonrev_credential_subproof_auxiliary_t nrcspa,
 nonrev_credential_subproof_tuple_c_t C);

#endif // __IDEMIX_NONREV_CREDENTIAL_SUBPROOF_DUMP_T_H__
