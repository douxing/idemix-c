#ifndef __IDEMIX_NON_REVOCATION_CREDENTIAL_SUBCHECK_T_H__
#define __IDEMIX_NON_REVOCATION_CREDENTIAL_SUBCHECK_T_H__

#include <pbc/pbc.h>
#include "idemix_mpz_vec.h"
#include "idemix_accumulator.h"
#include "idemix_non_revocation_key.h"
#include "idemix_non_revocation_credential_subproof_tuple_c.h"
#include "idemix_non_revocation_credential_subproof.h"

void nonrev_credential_subproof_t_into_vec
(mpz_vec_t T,
 pairing_t pairing,
 mpz_t CH,
 accumulator_t acc,
 accumulator_pk_t accpk,
 nonrev_pk_t pk,
 tuple_x_t X, // de facto nonrev_credential_subproof_t 
 nonrev_credential_subproof_tuple_c_t C);

#endif // __IDEMIX_NON_REVOCATION_CREDENTIAL_SUBCHECK_T_H__
