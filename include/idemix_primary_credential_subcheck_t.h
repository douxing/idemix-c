#ifndef __IDEMIX_PRIMARY_CREDENTIAL_SUBCHECK_T_H__
#define __IDEMIX_PRIMARY_CREDENTIAL_SUBCHECK_T_H__

#include <pbc/pbc.h>
#include "idemix_issuer_key.h"
#include "idemix_attribute.h"
#include "idemix_primary_credential_subproof_tuple_c.h"
#include "idemix_primary_credential_subproof.h"

// Eq. (54)
void primary_credential_subcheck_t_into_vec
(mpz_vec_t T,
 issuer_pk_t pk,
 mpz_t CH,
 attr_vec_t v,
 primary_credential_subproof_t pcsp);

#endif // __IDEMIX_PRIMARY_CREDENTIAL_SUBCHECK_T_H__
