#ifndef __IDEMIX_PRIMARY_CREDENTIAL_SUBPROOF_T_H__
#define __IDEMIX_PRIMARY_CREDENTIAL_SUBPROOF_T_H__

#include <gmp.h>
#include "idemix_mpz_vec.h"
#include "idemix_issuer_key.h"
#include "idemix_attribute.h"
#include "idemix_primary_credential_subproof_auxiliary.h"
#include "idemix_primary_credential_subproof_tuple_c.h"


void primary_credential_subproof_dump_t
(mpz_vec_t T,
 issuer_pk_t pk,
 attr_vec_t m_tildes,  // intersection(Cs, Ar)
 primary_credential_subproof_auxiliary_t pcspa,
 primary_credential_subproof_tuple_c_t C);

#endif // __IDEMIX_PRIMARY_CREDENTIAL_SUBPROOF_T_H__

