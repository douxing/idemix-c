#ifndef __IDEMIX_PREDICATE_SUBPROOF_H__
#define __IDEMIX_PREDICATE_SUBPROOF_H__

#include <pbc/pbc.h>
#include "idemix_mpz_vec.h"
#include "idemix_credentials.h"

enum operator {
  LESS_THAN_OR_EQUAL_TO,
  LESS_THAN,
  GREATER_THAN_OR_EQUAL_TO,
  GREATER_THAN,
};

struct predicate_s {
  enum operator op;
  mpz_t m;
  mpz_t z;
};
typedef struct predicate_s *predicate_ptr;
typedef struct predicate_s predicate_t[1];

void predicate_init_assign
(predicate_t p, // OUT
 enum operator op,
 mpz_t m,
 mpz_t z);

struct predicate_subproof_prepare_s {
  mpz_t delta;         // determined by op
  mpz_t u[4];          // 7.2.(Validity Proof).4.2

  mpz_t m_tilde;       // 7.2.(Validity Proof).1

  mpz_t r_delta;       // 7.2.(Validity Proof).4.3
  mpz_t r[4];          // 7.2.(Validity Proof).4.3

  
  mpz_t T[4];          // 7.2.(Validity Proof).4.4 add to C
  mpz_t T_delta;       // 7.2.(Validity Proof).4.4 add to C

  mpz_t u_tilde[4];    // 7.2.(Validity Proof).4.5

  mpz_t r_delta_tilde; // 7.2.(Validity Proof).4.6
  mpz_t r_tilde[4];    // 7.2.(Validity Proof).4.6

  mpz_t alpha_tilde;   // 7.2.(Validity Proof).4.7

  mpz_t T_bar[4];      // 7.2.(Validity Proof).4.8 add to T
  mpz_t T_delta_bar;   // 7.2.(Validity Proof).4.8 add to T
  mpz_t Q;             // 7.2.(Validity Proof).4.8 add to T
};
typedef struct predicate_subproof_prepare_s *predicate_subproof_prepare_ptr;
typedef struct predicate_subproof_prepare_s predicate_subproof_prepare_t[1];

void predicate_subproof_prepare_init(predicate_subproof_prepare_t);

void predicate_subproof_prepare_assign
(predicate_subproof_prepare_t psp_prep,
 predicate_t p,
 issuer_pk_t pk);

void predicate_subproof_prepare_into_CT
(mpz_vec_t C, // OUT
 mpz_vec_t T, // OUT
 predicate_subproof_prepare_t r);

struct predicate_subproof_s {
  mpz_t u_caret[4];   // Eq. (45)
  mpz_t r_caret[4];   // Eq. (46)
  mpz_t r_delta_caret; // Eq. (47)
  mpz_t alpha_caret;   // Eq. (48)
  mpz_t m_caret;
};
typedef struct predicate_subproof_s *predicate_subproof_ptr;
typedef struct predicate_subproof_s predicate_subproof_t[1];

void predicate_subproof_init
(predicate_subproof_t psp);

void predicate_subproof_assign
(predicate_subproof_t psp,
 mpz_t CH,
 predicate_t p,
 predicate_subproof_prepare_t psp_prep);

#endif // __IDEMIX_PREDICATE_SUBPROOF_H__
