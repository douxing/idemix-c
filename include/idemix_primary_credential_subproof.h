#ifndef __IDEMIX_PRIMARY_SUBPROOF_H__
#define __IDEMIX_PRIMARY_SUBPROOF_H__

#include <gmp.h>
#include "idemix_attribute.h"
#include "idemix_issuer_key.h"
#include "idemix_primary_credential.h"

// used in 7.2.(Validity proof) and 7.2.2

struct primary_credential_subproof_prepare_s {
  mpz_t r;       // 2128 bits
  mpz_t A_apos;  // Eq. (33)

  mpz_t v_apos;  // v - e*r Eq. (33)
  mpz_t e_apos;  // e - 2^596
  mpz_t v_tilde; // 3060 bits
  mpz_t e_tilde; // 456  bits
  
  mpz_t T; // Eq. (34)
};
typedef struct primary_credential_subproof_prepare_s \
               *primary_credential_subproof_prepare_ptr;
typedef struct primary_credential_subproof_prepare_s \
               primary_credential_subproof_prepare_t[1];

void primary_credential_subproof_prepare_init
(primary_credential_subproof_prepare_t);

void primary_credential_subproof_prepare_clear
(primary_credential_subproof_prepare_t);

void primary_credential_subproof_prepare_assign
(primary_credential_subproof_prepare_t pspr,
 attr_vec_t m_tildes, // = Intersection(Cs, Ar_bar)
 primary_credential_t pc,
 issuer_pk_t pk);

// sub-proof for Credential Cp
struct primary_credential_subproof_s {
  mpz_t e_caret;
  mpz_t v_caret;

  attr_vec_t m_carets; // {mj_caret} = Intersection(Cs, Ar_bar)

  mpz_t A_apos; // set directly from primary_credential_subproof_prepare_s->A_apos
};
typedef struct primary_credential_subproof_s *primary_credential_subproof_ptr;
typedef struct primary_credential_subproof_s primary_credential_subproof_t[1];

void primary_credential_subproof_init(primary_credential_subproof_t p,
			   const unsigned long l);
void primary_credential_subproof_clear(primary_credential_subproof_t p);

void primary_credential_subproof_assign(primary_credential_subproof_t psp,
			     mpz_t CH, // result of Eq. (41)
			     attr_vec_t m_tildes, // Intersection(Cs, Ar_bar)
			     primary_credential_t pc,
			     primary_credential_subproof_prepare_t psp_prep);

#endif // __IDEMIX_PRIMARY_CREDENTIAL_SUBPROOF_H__
