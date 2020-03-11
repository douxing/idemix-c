#ifndef __IDEMIX_PRIMARY_SUBPROOF_H__
#define __IDEMIX_PRIMARY_SUBPROOF_H__

#include <gmp.h>
#include "idemix_attribute.h"
#include "idemix_issuer_key.h"
#include "idemix_primary_credential.h"
#include "idemix_primary_credential_subproof_auxiliary.h"

// used in 7.2.(Validity proof) and 7.2.2
// sub-proof for Credential Cp
struct primary_credential_subproof_s {
  mpz_t e_caret;
  mpz_t v_caret;

  attr_vec_t m_carets; // {mj_caret} = Intersection(Cs, Ar_bar)

  mpz_t A_apos; // set directly from primary_credential_subproof_prepare_s->A_apos
};
typedef struct primary_credential_subproof_s *primary_credential_subproof_ptr;
typedef struct primary_credential_subproof_s primary_credential_subproof_t[1];

void primary_credential_subproof_init
(primary_credential_subproof_t p,
 const unsigned long l);

void primary_credential_subproof_clear(primary_credential_subproof_t p);

void primary_credential_subproof_assign
(primary_credential_subproof_t pcsp,
 mpz_t CH,            // result of Eq. (41)
 attr_vec_t m_tildes, // Intersection(Cs, Ar_bar)
 primary_credential_t pc,
 primary_credential_subproof_auxiliary_t pcspa,
 mpz_t A_apos); // from tuple C

#endif // __IDEMIX_PRIMARY_CREDENTIAL_SUBPROOF_H__
