#ifndef __IDEMIX_PREDICATE_SUBCHECK_T_H__
#define __IDEMIX_PREDICATE_SUBCHECK_T_H__

#include <pbc/pbc.h>
#include "idemix_issuer_key.h"
#include "idemix_attribute.h"
#include "idemix_predicate.h"
#include "idemix_predicate_subproof_tuple_c.h"
#include "idemix_predicate_subproof.h"

// Eq. (55) (56) (57)
void predicate_subcheck_t_into_vec
(mpz_vec_t T,
 issuer_pk_t pk,
 mpz_t CH,
 predicate_t p,
 predicate_subproof_tuple_c_t C,
 predicate_subproof_t psp);

#endif // __IDEMIX_PREDICATE_SUBCHECK_T_H__
