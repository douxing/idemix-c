#ifndef __IDEMIX_ISSUER_H__
#define __IDEMIX_ISSUER_H__

#include "idemix_utils.h"
#include "idemix_schema.h"
#include "idemix_issuer_key.h"
#include "idemix_non_revocation_key.h"
#include "idemix_non_revocation_credential.h"
#include "idemix_primary_credential.h"

// chapter 5:

// 5.2 Primary Credential Issurance

// call this function before 'primary_pre_credential'
int verify_primary_pre_credential_prepare
(primary_pre_credential_prepare_t ppc_prep,
 issuer_pk_t pk,
 mpz_t n0);

void issue_primary_pre_credential
(primary_pre_credential_t ppc,  // OUT, known attributes already set in schema
 issuer_sk_t sk,
 issuer_pk_t pk,
 mpz_t U,   // from primary_pre_credential_prepare
 mpz_t n1); // from primary_pre_credential_prepare

// end of 5.2

// 5.3 Non-revocation Credential Issuance

void issue_nonrev_pre_credential
(nonrev_pre_credential_t nrpc, // OUT to holder
 accumulator_t acc, // OUT to ledger
 nonrev_pre_credential_prepare_t nrpc_prep,
 pairing_t pairing,
 nonrev_pk_t pk,
 nonrev_sk_t sk,
 mpz_t m2,
 unsigned long i,
 accumulator_pk_t acc_pk,
 accumulator_sk_t acc_sk);

// end of 5.3

// end of Chapter 5

// void init_CS(int attrc, char *attrv[], issuer_pk_t);

#endif
