#include "idemix_random.h"
#include "idemix_utils.h"
#include "idemix_predicate_subproof.h"

void predicate_init_assign
(predicate_t p, // OUT
 enum operator op,
 mpz_t m,
 mpz_t z)
{
  // assert op in enum operator
  p->op = op;
  mpz_init_set(p->m, m);
  mpz_init_set(p->z, z);
}

void predicate_subproof_prepare_init(predicate_subproof_prepare_t p)
{

  mpz_inits(p->r_delta,
	    p->r[0], p->r[1], p->r[2], p->r[3],
	    p->u_tilde[0], p->u_tilde[1], p->u_tilde[2], p->u_tilde[3],
	    p->r_delta_tilde,
	    p->r_tilde[0], p->r_tilde[1], p->r_tilde[2], p->r_tilde[3],
	    p->alpha_tilde);
}

void predicate_subproof_prepare_assign
(predicate_subproof_prepare_t psp_prep,
 predicate_t p)
{
  switch (p->op) {
  case LESS_THAN_OR_EQUAL_TO:    // m <= z
    mpz_sub(psp_prep->delta, p->z, p->m);
    break;
  case LESS_THAN:                // m <  z
    mpz_sub(psp_prep->delta, p->z, p->m);
    mpz_sub_ui(psp_prep->delta, psp_prep->delta, 1);
    break;
  case GREATER_THAN_OR_EQUAL_TO: // m >= z
    mpz_sub(psp_prep->delta, p->m, p->z);
    break;
  case GREATER_THAN:             // m >  z
    mpz_sub(psp_prep->delta, p->m, p->z);
    mpz_sub_ui(psp_prep->delta, psp_prep->delta, 1);
    break;
  default:
    printf("unknown operator: %d", p->op);
    return;
  }
  // assert delta >= 0

  decompose_to_4_squares(psp_prep->u, psp_prep->delta);


  random_num_exact_bits(psp_prep->m_tilde, 592);
  random_num_exact_bits(psp_prep->r_delta, 2128);
  random_num_exact_bits(psp_prep->r_delta_tilde, 672);

  for (unsigned long i = 0; i < 4; ++i) {
    random_num_exact_bits(psp_prep->r[i], 2128);    
    random_num_exact_bits(psp_prep->u_tilde[i], 592);
    random_num_exact_bits(psp_prep->r_tilde[i], 672);
  }

  random_num_exact_bits(psp_prep->alpha_tilde, 2787);
}

void predicate_subproof_prepare_into_CT
(mpz_vec_t C, // OUT
 mpz_vec_t T, // OUT
 predicate_subproof_prepare_t psp_prep,
 issuer_pk_t pk,
 mpz_t mj_tilde)
{
  // Eq. (36) ~ (40)
  mpz_t Q, t, tt;
  mpz_inits(Q, t, tt);
  mpz_powm(Q, pk->S, psp_prep->alpha_tilde, pk->n); // Eq. (40) 1/3

  // T1~T4
  for (unsigned long i = 0; i < 4; ++i) {
    mpz_powm(t,  pk->Z, psp_prep->u[i], pk->n);
    mpz_powm(tt, pk->S, psp_prep->r[i], pk->n);
    mpz_mul(t, t, tt);
    mpz_mod(t, t, pk->n);
    mpz_vec_append(C, t);
    mpz_powm(t, t, psp_prep->u_tilde[i], pk->n); // Eq. (40) 2/3
    mpz_mul(Q, Q, t);
    mpz_mul(Q, Q, pk->n);
  }

  // T_delta
  mpz_powm(t,  pk->Z, psp_prep->delta, pk->n);
  mpz_powm(tt, pk->S, psp_prep->r_delta, pk->n);
  mpz_mul(t, t, tt);
  mpz_mod(t, t, pk->n);
  mpz_vec_append(C, t);

  // T1_bar ~ T4_bar
  for (unsigned long i = 0; i < 4; ++i) {
    mpz_powm(t,  pk->Z, psp_prep->u_tilde[i], pk->n);
    mpz_powm(tt, pk->S, psp_prep->r_tilde[i], pk->n);
    mpz_mul(t, t, tt);
    mpz_mod(t, t, pk->n);
    mpz_vec_append(T, t);
  }

  // T_delta_bar
  mpz_powm(t,  pk->Z, mj_tilde, pk->n);
  mpz_powm(tt, pk->S, psp_prep->r_delta_tilde, pk->n);
  mpz_mul(t, t, tt);
  mpz_mod(t, t, pk->n);
  mpz_vec_append(T, t);

  mpz_vec_append(T, Q); // finish Q, Eq, (40) 3/3
  
  mpz_clears(Q, t, tt);
}

void predicate_subproof_init
(predicate_subproof_t p)
{
  mpz_inits(p->u_caret[0], p->u_caret[1], p->u_caret[2], p->u_caret[3],
	    p->r_caret[0], p->r_caret[1], p->r_caret[2], p->r_caret[3],
	    p->r_delta_caret,
	    p->alpha_caret,
	    p->m_caret);
}

void predicate_subproof_assign
(predicate_subproof_t psp,
 mpz_t CH,
 predicate_subproof_prepare_t psp_prep)
{
  mpz_t t;
  mpz_init(t);
  mpz_set(psp->alpha_caret, psp_prep->r_delta); // Eq. (48) 1 / 3

  for (unsigned long i = 0; i < 4; ++i) {
    // Eq. (45)
    mpz_mul(psp->u_caret[i], CH, psp_prep->u[i]);
    mpz_add(psp->u_caret[i], psp_prep->u_tilde[i], psp->u_caret[i]);

    // Eq. (46)
    mpz_mul(psp->r_caret[i], CH, psp_prep->u[i]);
    mpz_add(psp->r_caret[i], psp_prep->r_tilde[i], psp->r_caret[i]);

    // Eq. (48) 2 / 3
    mpz_mul(t, psp_prep->u[i], psp_prep->r[i]);
    mpz_sub(psp->alpha_caret, psp->alpha_caret, t);
  }

  // Eq. (47)
  mpz_mul(psp->r_delta_caret, CH, psp_prep->r_delta);
  mpz_add(psp->r_delta_caret, psp_prep->r_delta_tilde, psp->r_delta_caret);

  // Eq. (48) 3 / 3  
  mpz_mul(t, CH, psp->alpha_caret);
  mpz_add(psp->alpha_caret, psp_prep->alpha_tilde, t);

  mpz_mul(t, psp_prep->u[1], psp_prep->r[0]);
  mpz_mul(t, psp_prep->u[0], psp_prep->r[0]);
  mpz_mul(t, psp_prep->u[0], psp_prep->r[0]);


  mpz_clear(t);
}
