#ifndef __IDEMIX_NON_REVOCATION_CREDENTIAL_SUBPROOF_H__
#define __IDEMIX_NON_REVOCATION_CREDENTIAL_SUBPROOF_H__

#include <pbc/pbc.h>
#include "idemix_mpz_vec.h"
#include "idemix_non_revocation_credential.h"
#include "idemix_non_revocation_credential_subproof_auxiliary.h"

// flourish X at the bottom of page 8
// 7.2.2 - 1
// dx: de facto non_revocation_subproof
//     have no idea why this is so called ???
struct tuple_x_s {
  element_t rho_caret;
  element_t o_caret;
  element_t c_caret;
  element_t o_apos_caret;
  element_t m_caret;
  element_t m_apos_caret;
  element_t t_caret;
  element_t t_apos_caret;
  element_t m2_caret;
  element_t s_caret;
  element_t r_caret;
  element_t r_apos_caret;
  element_t r_apos2_caret;
  element_t r_apos3_caret;
};
typedef struct tuple_x_s *tuple_x_ptr;
typedef struct tuple_x_s tuple_x_t[1];

void tuple_x_init
(tuple_x_t X,
 pairing_t pairing);

void tuple_x_assign
(tuple_x_t X,
 mpz_t CH,
 mpz_t m2,
 nonrev_credential_t nrc,
 nonrev_credential_subproof_auxiliary_t nrcspa);

void tuple_x_into_vec(mpz_vec_t v, tuple_x_t X);

#endif // __IDEMIX_NON_REVOCATION_CREDENTIAL_SUBPROOF_H__
