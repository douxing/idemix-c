#ifndef __IDEMIX_HODLER_H__
#define __IDEMIX_HODLER_H__

#include "idemix_utils.h"
#include "idemix_crypto.h"
#include "idemix_schema.h"
#include "idemix_credentials.h"

// Chapter 5:

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
 element_t s_apos,
 nr_pk_t pk);

// end of 5.1

// 5.4 Storeing Credentials

int verify_primary_pre_credential(pri_pre_cred_t ppc,
				  iss_pk_t pk,
				  mpz_t v,  // = v' + v"
				  mpz_t n2, // = ???
				  mpz_t m1);

void issue_primary_credential
(pri_cred_t pc, // OUT
 pri_pre_cred_t ppc,
 mpz_t v_apos); // v_apos is generated in 5.1 - 1


// end of 5.4

// end of Chapter 5

// Chapter 7



// end of Chapter 7

#endif
