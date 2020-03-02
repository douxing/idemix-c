#ifndef __IDEMIX_HODLER_H__
#define __IDEMIX_HODLER_H__

#include "idemix_utils.h"
#include "idemix_crypto.h"
#include "idemix_schema.h"
#include "idemix_credentials.h"

// 5.1 Holder Setup:

// Holder Setup prepares for primary credential
// m1: currently, only m1(link secret) is needed
void issue_primary_pre_credential_prepare
(pri_pre_cred_prep_t ppc_prep, // OUT
 mpz_t v_apos, // OUT for Holder itself
 iss_pk_t pk,
 mpz_t m1,
 mpz_t n0);

// Holder prepares for non-revokation credential
void issue_non_revok_pre_credential_prepare
(nr_pre_cred_prep_t nrpc_prep, // OUT
 pairing_t pairing,
 nr_pk_t pk);

// end of Chapter 5.1

#endif
