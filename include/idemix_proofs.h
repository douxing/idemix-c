#ifndef __IDEMIX_PROOFS_H__
#define __IDEMIX_PROOFS_H__

#include <pbc/pbc.h>

#include "idemix_mpz_vec.h"
#include "idemix_accumulator.h"

// Chapter 7

struct non_revok_proof_randomness_s {
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
typedef struct non_revok_proof_randomness_s *nr_proof_rand_ptr;
typedef struct non_revok_proof_randomness_s nr_proof_rand_t[1];

void non_rev_proof_rand_init_with_random(nr_proof_rand_t r, pairing_t p);

struct non_revok_proof_s {
  // page 7 Eq. (22)~(25), will be added to C
  element_t E; // in G1 
  element_t D; // in G1
  element_t A; // in G1
  element_t G; // in G1
  element_t W; // in G2
  element_t S; // in G2
  element_t U; // in G2

  // page 7 Eq. (26) (27)
  element_t m; // in Zr
  element_t t; // in Zr
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
typedef struct non_revok_proof_s *nr_proof_ptr;
typedef struct non_revok_proof_s nr_proof_t[1];

void non_revok_proof_init(nr_proof_t nrp, pairing_t p);

void nrp_to_C(mpz_vec_t C, // OUT
	      nr_proof_t nrp);

void nrp_to_T(mpz_vec_t T, // OUT
	      nr_proof_t nrp);



// end of Chapter 7

#endif
