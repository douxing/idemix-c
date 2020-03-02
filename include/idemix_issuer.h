#ifndef __IDEMIX_ISSUER_H__
#define __IDEMIX_ISSUER_H__

#include "idemix_utils.h"
#include "idemix_crypto.h"
#include "idemix_schema.h"
#include "idemix_credentials.h"

// chapter 5:

// 5.2 Primary Credential Issurance

// call this function before 'primary_pre_credential'
int verify_primary_pre_credential_prepare
(pri_pre_cred_prep_t ppc_prep,
 iss_pk_t pk,
 mpz_t n0);

void issue_primary_pre_credential
(pri_pre_cred_t ppc, // OUT
 pri_pre_cred_prep_t ppc_prep,
 iss_sk_t sk,
 iss_pk_t pk,
 schema_t schema);

// end of 5.2

// 5.3 Non-revocation Credential Issuance

void compute_m2(mpz_t m2,
		const mpz_t i,
		const mpz_t H_cop);

void issue_non_revok_pre_credential
(nr_pre_cred_t nrpc, // OUT to holder
 nr_pre_cred_prep_t nrpc_prep,
 pairing_t pairing,
 nr_pk_t pk,
 nr_sk_t sk,
 schema_t schema,
 accumulator_t acc,
 unsigned long i,
 accum_pk_t accum_pk,
 accum_sk_t accum_sk);

// end of 5.3

// end of Chapter 5

// void init_CS(int attrc, char *attrv[], iss_pk_t);

#endif
