#ifndef __IDEMIX_ISSUER_H__
#define __IDEMIX_ISSUER_H__

#include <gmp.h>
#include "idemix_issuer_key.h"
#include "idemix_primary_credential.h"

int verify_primary_pre_credential_prepare
(primary_pre_credential_prepare_t ppc_prep,
 issuer_pk_t pk,
 mpz_t n0);

void issue_primary_pre_credential
(primary_pre_credential_t ppc, // OUT, known attributes already set in schema
 issuer_sk_t sk,
 issuer_pk_t pk,
 mpz_t U,   // from primary_pre_credential_prepare
 mpz_t n1); // from primary_pre_credential_prepare


#endif // __IDEMIX_ISSUER_H__
