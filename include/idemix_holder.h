#ifndef __IDEMIX_HODLER_H__
#define __IDEMIX_HODLER_H__

#include "sm3.h"

struct prepare_primary_credential_s {
  mpz_t U;
  mpz_t c;
  mpz_t v_apos_caret;
  mpz_t m1_caret; // only m1(link secret) is needed
  mpz_t n1;
};
typedef struct prepare_primary_credential_s *pre_prim_cred_ptr;
typedef struct prepare_primary_credential_s pre_prim_cred_t[1];

struct prepare_non_revokation_credential_s {
  element_t U;
};
typedef struct prepare_non_revokation_credential_s *pre_nonrev_cred_ptr;
typedef struct prepare_non_revokation_credential_s pre_nonrev_cred_t[1];

// 5.1 Holder Setup prepares for primary credential
void prepare_primary_credential(issuer_pk_t pk, mpz_t m1, mpz_t n0,
				pre_prim_cred_t ppc);

// 5.1 Holder Setup - prepares for non-revokation credential
void prepare_non_revokation_credential(pairing_t pairing, revok_pk_t pk, pre_nonrev_cred_t pnrc);

#endif
