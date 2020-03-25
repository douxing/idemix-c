#ifndef __IDEMIX_PREDICATE_SUBPROOF_H__
#define __IDEMIX_PREDICATE_SUBPROOF_H__

#include <pbc/pbc.h>
#include "idemix_mpz_vec.h"
#include "idemix_issuer_key.h"
#include "idemix_predicate.h"
#include "idemix_predicate_subproof_auxiliary.h"

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

void predicate_subproof_clear
(predicate_subproof_t psp);

void predicate_subproof_assign
(predicate_subproof_t psp,
 mpz_t CH,
 predicate_t p,
 predicate_subproof_auxiliary_t pspa);

#endif // __IDEMIX_PREDICATE_SUBPROOF_H__
