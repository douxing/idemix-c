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

  mpz_inits(p->delta,
	    p->u[0], p->u[1], p->u[2], p->u[3],
	    p->m_tilde,
	    p->r_delta,
	    p->r[0], p->r[1], p->r[2], p->r[3],
	    p->T[0], p->T[1], p->T[2], p->T[3],
	    p->T_delta,
	    p->u_tilde[0], p->u_tilde[1], p->u_tilde[2], p->u_tilde[3],
	    p->r_delta_tilde,
	    p->r_tilde[0], p->r_tilde[1], p->r_tilde[2], p->r_tilde[3],
	    p->alpha_tilde,
	    p->T_bar[0], p->T_bar[1], p->T_bar[2], p->T_bar[3],
	    p->T_delta_bar,
	    p->Q);
}

void predicate_subproof_prepare_assign
(predicate_subproof_prepare_t psp_prep,
 predicate_t p,
 issuer_pk_t pk)
{
  switch (p->op) { // assign delta
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

  decompose_to_4_squares(psp_prep->u, psp_prep->delta); // assgin u1 u2 u3 u4

  random_num_exact_bits(psp_prep->m_tilde, 592); // 7.2.(Validity Proof).1

  random_num_exact_bits(psp_prep->r_delta, 2128);
  random_num_exact_bits(psp_prep->r_delta_tilde, 672);

  for (unsigned long i = 0; i < 4; ++i) {
    random_num_exact_bits(psp_prep->r[i], 2128);    
    random_num_exact_bits(psp_prep->u_tilde[i], 592);
    random_num_exact_bits(psp_prep->r_tilde[i], 672);
  }

  random_num_exact_bits(psp_prep->alpha_tilde, 2787);

  // Eq. (36) ~ (40)
  mpz_t t;
  mpz_init(t);
  mpz_powm(psp_prep->Q, pk->S, psp_prep->alpha_tilde, pk->n); // Eq. (40) 1/2

  // T1~T4 T1bar~T4bar
  for (unsigned long i = 0; i < 4; ++i) {
    // Eq. (36)
    mpz_powm(psp_prep->T[i], pk->Z, psp_prep->u[i], pk->n);
    mpz_powm(t, pk->S, psp_prep->r[i], pk->n);
    mpz_mul(psp_prep->T[i], psp_prep->T[i], t);
    mpz_mod(psp_prep->T[i], psp_prep->T[i], pk->n);

    // Eq. (38)
    mpz_powm(psp_prep->T_bar[i], pk->Z, psp_prep->u_tilde[i], pk->n);
    mpz_powm(t, pk->S, psp_prep->r_tilde[i], pk->n);
    mpz_mul(psp_prep->T_bar[i], psp_prep->T_bar[i], t);
    mpz_mod(psp_prep->T_bar[i], psp_prep->T_bar[i], pk->n);

    mpz_powm(t, psp_prep->T[i], psp_prep->u_tilde[i], pk->n); // Eq. (40) 2/2
    mpz_mul(psp_prep->Q, psp_prep->Q, t);
    mpz_mul(psp_prep->Q, psp_prep->Q, pk->n);
  }

  // Eq. (37) T_delta
  mpz_powm(psp_prep->T_delta, pk->Z, psp_prep->delta, pk->n);
  mpz_powm(t, pk->S, psp_prep->r_delta, pk->n);
  mpz_mul(psp_prep->T_delta, psp_prep->T_delta, t);
  mpz_mod(psp_prep->T_delta, psp_prep->T_delta, pk->n);

  // Eq. (39) T_delta_bar
  mpz_powm(psp_prep->T_delta_bar, pk->Z, psp_prep->m_tilde, pk->n);
  mpz_powm(t, pk->S, psp_prep->r_delta_tilde, pk->n);
  mpz_mul(psp_prep->T_delta_bar, psp_prep->T_delta_bar, t);
  mpz_mod(psp_prep->T_delta_bar, psp_prep->T_delta_bar, pk->n);
  
  mpz_clear(t);
}

void predicate_subproof_prepare_into_CT
(mpz_vec_t C, // OUT
 mpz_vec_t T, // OUT
 predicate_subproof_prepare_t psp_prep)
{
  for (unsigned long i = 0; i < 4; ++i) {
    mpz_vec_append(C, psp_prep->T[i]);
    mpz_vec_append(T, psp_prep->T_bar[i]);
  }

  mpz_vec_append(C, psp_prep->T_delta);
  mpz_vec_append(T, psp_prep->T_delta_bar);  
  mpz_vec_append(T, psp_prep->Q);
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
 predicate_t p,
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

  // set mj_caret
  mpz_mul(psp->m_caret, CH, p->m);
  mpz_add(psp->m_caret, psp_prep->m_tilde, psp->m_caret);

  mpz_clear(t);
}
