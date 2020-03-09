#ifndef __IDEMIX_NON_REVOCATION_SUBPROOF_H__
#define __IDEMIX_NON_REVOCATION_SUBPROOF_H__

#include <pbc/pbc.h>

#include "idemix_mpz_vec.h"
#include "idemix_accumulator.h"
#include "idemix_credentials.h"

// used in 7.2.(Non-revocation proof) and 7.2.2

struct nonrev_subproof_rand_s {
  // page 7 - 5. Select random ... mod q
  element_t rho;
  element_t rho_apos;
  element_t r;
  element_t r_apos;
  element_t r_apos2;
  element_t r_apos3;
  element_t o;
  element_t o_apos;

  // page 7 -  8. Generate random ... mod q 
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
typedef struct nonrev_subproof_rand_s *nonrev_subproof_rand_ptr;
typedef struct nonrev_subproof_rand_s nonrev_subproof_rand_t[1];

void nonrev_subproof_rand_init_random
(nonrev_subproof_rand_t r,
 pairing_t p);

struct nonrev_subproof_s {
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
  element_t T1_bar; // in G1
  element_t T2_bar; // in G1
  element_t T3_bar; // in GT
  element_t T4_bar; // in GT
  element_t T5_bar; // in G1
  element_t T6_bar; // in G1
  element_t T7_bar; // in GT
  element_t T8_bar; // in GT
};
typedef struct nonrev_subproof_s *nonrev_subproof_ptr;
typedef struct nonrev_subproof_s nonrev_subproof_t[1];

void nonrev_subproof_init
(nonrev_subproof_t nrsp, // OUT
 pairing_t p);

void nonrev_subproof_into_C
(mpz_vec_t C,            // OUT
 nonrev_subproof_t nrsp);

void nonrev_subproof_into_T
(mpz_vec_t T,            // OUT
 nonrev_subproof_t nrsp);

#endif // __IDEMIX_NON_REVOCATION_SUBPROOF_H__
