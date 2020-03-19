#ifndef __IDEMIX_PREDICATE_SUBPROOF_DUMP_T_H__
#define __IDEMIX_PREDICATE_SUBPROOF_DUMP_T_H__

#include <gmp.h>
#include "idemix_issuer_key.h"
#include "idemix_predicate_subproof_auxiliary.h"
#include "idemix_predicate_subproof_tuple_c.h"

void predicate_subproof_dump_t
(mpz_vec_t T,
 issuer_pk_t pk,
 predicate_subproof_auxiliary_t pspa,
 predicate_subproof_tuple_c_t C);

#endif // __IDEMIX_PREDICATE_SUBPROOF_DUMP_T_H__
