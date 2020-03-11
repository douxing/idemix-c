#ifndef __IDEMIX_NON_REVOCATION_CREDENTIAL_SUBPROOF_AUXILIARY_H__
#define __IDEMIX_NON_REVOCATION_CREDENTIAL_SUBPROOF_AUXILIARY_H__

#include <pbc/pbc.h>
#include "idemix_non_revocation_credential.h"

// 7.2
// Non-revocation subproof prover's auxant data structure
struct nonrev_credential_subproof_auxiliary_s {
  // page 7 - 5. Select aux ... mod q in Zr
  element_t rho;
  element_t rho_apos;
  element_t r;
  element_t r_apos;
  element_t r_apos2;
  element_t r_apos3;
  element_t o;
  element_t o_apos;

  // page 7 - 7 Compute m,t,m',t' Eq. (26) (27)
  element_t m;      // in Zr
  element_t t;      // in Zr
  element_t m_apos; // in Zr
  element_t t_apos; // in Zr

  // page 7 - 8. Generate aux ... mod q in Zr
  element_t rho_tilde;
  element_t o_tilde;
  element_t o_apos_tilde;
  element_t c_tilde;
  element_t m_tilde;
  element_t m_apos_tilde;
  element_t t_tilde;
  element_t t_apos_tilde;
  element_t m2_tilde;
  element_t s_tilde;
  element_t r_tilde;
  element_t r_apos_tilde;
  element_t r_apos2_tilde;
  element_t r_apos3_tilde;
};
typedef struct nonrev_credential_subproof_auxiliary_s \
               *nonrev_credential_subproof_auxiliary_ptr;
typedef struct nonrev_credential_subproof_auxiliary_s \
               nonrev_credential_subproof_auxiliary_t[1];

void nonrev_credential_subproof_auxiliary_init
(nonrev_credential_subproof_auxiliary_t nrcspa,
 pairing_t pairing);

void nonrev_credential_subproof_auxiliary_clear
(nonrev_credential_subproof_auxiliary_t nrcspa);

void nonrev_credential_subproof_auxiliary_assign
(nonrev_credential_subproof_auxiliary_t nrcspa,
 nonrev_credential_t nrc);

#endif // __IDEMIX_NON_REVOCATION_CREDENTIAL_SUBPROOF_AUXILIARY_H__
