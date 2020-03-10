#ifndef __IDEMIX_NON_REVOCATION_SUBPROOF_H__
#define __IDEMIX_NON_REVOCATION_SUBPROOF_H__

#include <pbc/pbc.h>

#include "idemix_mpz_vec.h"
#include "idemix_crypto.h"
#include "idemix_credentials.h"
#include "idemix_accumulator.h"

// used in 7.2.(Non-revocation proof) and 7.2.2

struct nonrev_subproof_prepare_s {
  // page 7 - 5. Select random ... mod q in Zr
  element_t rho;
  element_t rho_apos;
  element_t r;
  element_t r_apos;
  element_t r_apos2;
  element_t r_apos3;
  element_t o;
  element_t o_apos;

  // page 7 - 8. Generate random ... mod q in Zr
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

  // page 7 Eq. (22)~(25), will be added to C
  element_t E; // in G1
  element_t D; // in G1
  element_t A; // in G1
  element_t G; // in G1
  element_t W; // in G2
  element_t S; // in G2
  element_t U; // in G2

  // page 7 Eq. (26) (27)
  element_t m;      // in Zr
  element_t t;      // in Zr
  element_t m_apos; // in Zr
  element_t t_apos; // in Zr

  // page 7 Eq. (28)~(32) will be added to T
  element_t T_bar[8]; // 1,2,5,6 in G1, 3,4,7,8 in GT
};
typedef struct nonrev_subproof_prepare_s *nonrev_subproof_prepare_ptr;
typedef struct nonrev_subproof_prepare_s nonrev_subproof_prepare_t[1];

void nonrev_subproof_prepare_init
(nonrev_subproof_prepare_t nrsp_prep, // OUT
 pairing_t pairing);

void nonrev_subproof_prepare_assign
(nonrev_subproof_prepare_t nrsp_prep,
 nonrev_pk_t pk,
 nonrev_credential_t nrc,

 accumulator_t acc);

void nonrev_subproof_prepare_into_CT
(mpz_vec_t C, // OUT
 mpz_vec_t T, // OUT
 nonrev_subproof_prepare_t nrsp_prep);

// dx: this is the big X at the bottom of page 8
// 7.2.2 - 1
struct nonrev_subproof_s {
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
typedef struct nonrev_subproof_s *nonrev_subproof_ptr;
typedef struct nonrev_subproof_s nonrev_subproof_t[1];

void nonrev_subproof_init
(nonrev_subproof_t nrsp,
 pairing_t pairing);

void nonrev_subproof_assign
(nonrev_subproof_t nrsp,
 mpz_t CH,
 mpz_t m2,
 nonrev_credential_t nrc,
 nonrev_subproof_prepare_t nrsp_prep);


#endif // __IDEMIX_NON_REVOCATION_SUBPROOF_H__
