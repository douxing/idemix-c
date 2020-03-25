#ifndef __IDEMIX_PRIMARY_CREDENTIAL_SUBPROOF_AUXILIARY_H__
#define __IDEMIX_PRIMARY_CREDENTIAL_SUBPROOF_AUXILIARY_H__

#include <pbc/pbc.h>
#include "idemix_attribute.h"
#include "idemix_primary_credential.h"
#include "idemix_issuer_key.h"

// Validity proof prover's auxant data structure
// for each credential Cp and Issuer's public key pk_I:
struct primary_credential_subproof_auxiliary_s {
  mpz_t r;       // 2128 bits

  mpz_t v_apos;  // v - e*r Eq. (33)
  mpz_t e_apos;  // e - 2^596
  mpz_t v_tilde; // 3060 bits
  mpz_t e_tilde; // 456  bits
};
typedef struct primary_credential_subproof_auxiliary_s \
               *primary_credential_subproof_auxiliary_ptr;
typedef struct primary_credential_subproof_auxiliary_s \
               primary_credential_subproof_auxiliary_t[1];

void primary_credential_subproof_auxiliary_init
(primary_credential_subproof_auxiliary_t aux);

void primary_credential_subproof_auxiliary_clear
(primary_credential_subproof_auxiliary_t aux);

void primary_credential_subproof_auxiliary_assign
(primary_credential_subproof_auxiliary_t pcspa,
 primary_credential_t pc);

#endif // __IDEMIX_PRIMARY_CREDENTIAL_SUBPROOF_AUXILIARY_H__
