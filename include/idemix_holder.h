#ifndef __IDEMIX_HODLER_H__
#define __IDEMIX_HODLER_H__

#include "sm3.h"

// Chapter 5:

struct primary_pre_credential_prepare_s {
  mpz_t U;
  mpz_t c;
  mpz_t v_apos_caret;
  mpz_t m1_caret; // only m1(link secret) is needed
  mpz_t n1;
};
typedef struct primary_pre_credential_prepare_s *prim_pre_cred_prep_ptr;
typedef struct primary_pre_credential_prepare_s prim_pre_cred_prep_t[1];

struct non_revokation_pre_credential_prepare_s {
  element_t U; // in G1
};
typedef struct non_revokation_pre_credential_prepare_s *nonrev_pre_cred_prep_ptr;
typedef struct non_revokation_pre_credential_prepare_s nonrev_pre_cred_prep_t[1];

struct primary_credential_s {
};


// 5.1 Holder Setup prepares for primary credential
void issue_primary_pre_credential_prepare(issuer_pk_t pk, mpz_t m1, mpz_t n0,
					  prim_pre_cred_prep_t ppcp);

// 5.1 Holder Setup - prepares for non-revokation credential
void issue_non_revokation_pre_credential_prepare(pairing_t pairing,
						 nonrev_pk_t pk,
						 nonrev_pre_cred_prep_t nrpcp);

// end of Chapter 5

#endif
