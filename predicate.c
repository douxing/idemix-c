#include "idemix_predicate.h"
#include "idemix_random.h"

void predicate_init_with_params
(predicate_t p, // OUT
 enum operator op,
 mpz_t m,
 mpz_t z)
{
  // assert op in enum operator
  p->op = op;
  mpz_inits(p->z,
	    p->m,
	    p->delta,
	    p->u1,
	    p->u2,
	    p->u3,
	    p->u4,
	    p->r_delta,
	    p->r1,
	    p->r2,
	    p->r3,
	    p->r4,
	    p->u1_tilde,
	    p->u1_tilde,
	    p->u2_tilde,
	    p->u3_tilde,
	    p->u4_tilde,
	    p->r_delta_tilde,
	    p->r1_tilde,
	    p->r2_tilde,
	    p->r3_tilde,
	    p->r4_tilde,
	    p->alpha_tilde);
  mpz_set(p->m, m);
  mpz_set(p->z, z);

  switch (op) {
  case LESS_THAN_OR_EQUAL_TO:    // m <= z
    mpz_sub(p->delta, z, m);
    break;
  case LESS_THAN:                // m <  z
    mpz_sub(p->delta, z, m);
    mpz_sub_ui(p->delta, p->delta, 1);
    break;
  case GREATER_THAN_OR_EQUAL_TO: // m >= z
    mpz_sub(p->delta, m, z);
    break;
  case GREATER_THAN:             // m >  z
    mpz_sub(p->delta, m, z);
    mpz_sub_ui(p->delta, p->delta, 1);
    break;
  default:
    printf("unknown operator: %d", op);
    return;
  }
  // assert delta >= 0

  decompose_to_4_squares(p->delta, p->u1, p->u2, p->u3, p->u4);

  random_num_exact_bits(p->r_delta, 2128);
  random_num_exact_bits(p->r1, 2128);
  random_num_exact_bits(p->r2, 2128);
  random_num_exact_bits(p->r3, 2128);
  random_num_exact_bits(p->r4, 2128);

  random_num_exact_bits(p->u1_tilde, 592);
  random_num_exact_bits(p->u2_tilde, 592);
  random_num_exact_bits(p->u3_tilde, 592);
  random_num_exact_bits(p->u4_tilde, 592);

  random_num_exact_bits(p->r_delta_tilde, 672);
  random_num_exact_bits(p->r1_tilde, 672);
  random_num_exact_bits(p->r2_tilde, 672);
  random_num_exact_bits(p->r3_tilde, 672);
  random_num_exact_bits(p->r4_tilde, 672);

  random_num_exact_bits(p->alpha_tilde, 2787);
}
