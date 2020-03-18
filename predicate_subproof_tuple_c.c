#include "idemix_predicate_subproof_tuple_c.h"

void predicate_subproof_tuple_c_init
(predicate_subproof_tuple_c_t C)
{
  mpz_inits(C->T[0],
	    C->T[1],
	    C->T[2],
	    C->T[3],
	    C->T_delta,
	    NULL);
}

void predicate_subproof_tuple_c_clear
(predicate_subproof_tuple_c_t C)
{
  mpz_clears(C->T[0],
	     C->T[1],
	     C->T[2],
	     C->T[3],
	     C->T_delta,
	     NULL);
}

void predicate_subproof_tuple_c_assign
(predicate_subproof_tuple_c_t C,
 issuer_pk_t pk,
 predicate_subproof_auxiliary_t pspa)
{
  mpz_t t;
  mpz_init(t);
  for (unsigned long i = 0; i < 4; ++i) {        // Eq. (36)
    mpz_powm(t, pk->Z, pspa->u[i], pk->n);       // Z^ui
    mpz_powm(C->T[i], pk->S, pspa->r[i], pk->n); // S^ri
    mpz_mul(C->T[i], t, C->T[i]);
    mpz_mod(C->T[i], C->T[i], pk->n);
  }

  // Eq. (36)
  mpz_powm(t, pk->Z, pspa->delta, pk->n);            // Z^delta
  mpz_powm(C->T_delta, pk->S, pspa->r_delta, pk->n); // S^r_delta
  mpz_mul(C->T_delta, t, C->T_delta);
  mpz_mod(C->T_delta, C->T_delta, pk->n);
  mpz_clear(t);
}

void predicate_subproof_tuple_c_into_vec
(mpz_vec_t v,
 predicate_subproof_tuple_c_t C)
{
  mpz_vec_append(v, C->T[0]);
  mpz_vec_append(v, C->T[1]);
  mpz_vec_append(v, C->T[2]);
  mpz_vec_append(v, C->T[3]);
  mpz_vec_append(v, C->T_delta);
}
