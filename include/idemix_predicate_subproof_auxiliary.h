#ifndef __IDEMIX_PREDICATE_SUBPROOF_AUXILIARY_H__
#define __IDEMIX_PREDICATE_SUBPROOF_AUXILIARY_H__

#include <pbc/pbc.h>
#include "idemix_predicate.h"
#include "idemix_issuer_key.h"

// Validity proof prover's auxant data structure
// for each credential Cp and Issuer's public key pk_I:
struct predicate_subproof_auxiliary_s {
  mpz_t delta;         // determined by op, delta = u1^2 + u2^2 + u3^2 + u4^2
  mpz_t u[4];          // 7.2.(Validity Proof).4.2

  mpz_t m_tilde;       // 7.2.(Validity Proof).1

  mpz_t r_delta;       // 7.2.(Validity Proof).4.3
  mpz_t r[4];          // 7.2.(Validity Proof).4.3

  mpz_t u_tilde[4];    // 7.2.(Validity Proof).4.5

  mpz_t r_delta_tilde; // 7.2.(Validity Proof).4.6
  mpz_t r_tilde[4];    // 7.2.(Validity Proof).4.6

  mpz_t alpha_tilde;   // 7.2.(Validity Proof).4.7
};
typedef struct predicate_subproof_auxiliary_s \
               *predicate_subproof_auxiliary_ptr;
typedef struct predicate_subproof_auxiliary_s \
               predicate_subproof_auxiliary_t[1];

void predicate_subproof_auxiliary_init
(predicate_subproof_auxiliary_t pspa);

void predicate_subproof_auxiliary_clear
(predicate_subproof_auxiliary_t pspa);

void predicate_subproof_auxiliary_assign
(predicate_subproof_auxiliary_t pspa,
 predicate_t p);

#endif // __IDEMIX_PREDICATE_SUBPROOF_AUXILIARY_H__


