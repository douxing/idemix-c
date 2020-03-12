#include "idemix_predicate_subproof_t.h"

void predicate_subproof_t_into_vec
(mpz_vec_t T,
 issuer_pk_t pk,
 predicate_subproof_auxiliary_t pspa,
 predicate_subproof_tuple_c_t C)
{
  mpz_t t1, t2;
  mpz_inits(t1, t2);

  // T1_bar ~ T4_bar Eq. (38)
  for (unsigned long i = 0; i < 4; ++i) {
    mpz_powm(t1, pk->Z, pspa->u_tilde[i], pk->n);
    mpz_powm(t2, pk->S, pspa->r_tilde[i], pk->n);
    mpz_mul(t1, t1, t2);
    mpz_mod(t1, t1, pk->n);
    mpz_vec_append(T, t1);
  }

  // T_delta_bar Eq. (39)
  mpz_powm(t1, pk->Z, pspa->m_tilde, pk->n);
  mpz_powm(t2, pk->S, pspa->r_delta_tilde, pk->n);
  mpz_mul(t1, t1, t2);
  mpz_mod(t1, t1, pk->n);
  mpz_vec_append(T, t1);

  // Q Eq. (40)
  mpz_set_ui(t2, 1);
  for (unsigned long i = 0; i < 4; ++i) {
    mpz_powm(t1, C->T[i], pspa->u_tilde[i], pk->n);
    mpz_mul(t2, t2, t1);
    mpz_mod(t2, t2, pk->n);
  }
  mpz_powm(t1, pk->S, pspa->alpha_tilde, pk->n);
  mpz_mul(t1, t1, t2);
  mpz_mod(t1, t1, pk->n);
  mpz_vec_append(T, t1);  

  mpz_clears(t1, t2);
}
