#include <assert.h>
#include "idemix_primary_pre_credential.h"
#include "idemix_random.h"

void primary_pre_credential_init
(primary_pre_credential_t ppc,
 schema_t s)
{
  mpz_inits(ppc->A,
	    ppc->e,
	    ppc->v_apos_apos,
	    ppc->s_e,
	    ppc->c_apos,
	    NULL);
  attr_vec_init(ppc->Ak, schema_attr_cnt_known(s));
}

void primary_pre_credential_clear
(primary_pre_credential_t ppc)
{
  mpz_clears(ppc->A,
	     ppc->e,
	     ppc->v_apos_apos,
	     ppc->s_e,
	     ppc->c_apos,
	     NULL);
  attr_vec_clear(ppc->Ak);
}

void primary_pre_credential_assign
(primary_pre_credential_t ppc,
 issuer_pk_t pk,
 issuer_sk_t sk,
 attr_vec_t Ak,
 primary_pre_credential_prepare_t ppc_prep)
{
  // temporary variables;
  mpz_t temp, t;
  mpz_inits(temp, t, NULL);

  // Issuer prepare the credential:
  // 1. Compute m2 <- H(i||H_cop)
  //    done by caller, in schema

  // 2. set attributes from Ak
  attr_vec_set(ppc->Ak, Ak);

  // 3. Generate random 2724-bit number v" with most significant bit equal 1
  //    and random prime e such that 2^596 <= e <= 2^596 + 2^119
  random_num_exact_bits(ppc->v_apos_apos, 2724);

  // page 5 Eq. (10)
  mpz_set_ui(temp, 0);
  mpz_setbit(temp, 596); // low bound
  mpz_set(t, temp);
  mpz_setbit(t, 119);
  mpz_add_ui(t, t, 1);  // high bound
  random_prime_range(ppc->e, temp, t);

  // 4 Compute Q Eq. (11) page 5
  mpz_t Q;
  mpz_init_set(Q, ppc_prep->U);
  mpz_powm(temp, pk->S, ppc->v_apos_apos, pk->n);
  mpz_mul(Q, Q, temp);
  mpz_mod(Q, Q, pk->n);
  for (unsigned long i = 0; i < attr_vec_size(ppc->Ak); ++i) {
    attr_ptr mi_p = attr_vec_head(ppc->Ak) + i;
    mpz_powm(temp, pk->R_v + mi_p->i, mi_p->v, pk->n);
    mpz_mul(Q, Q, temp);
    mpz_mod(Q, Q, pk->n);
  }
  mpz_invert(Q, Q, pk->n);
  mpz_mul(Q, pk->Z, Q);
  mpz_mod(Q, Q, pk->n);

  // page 5 Eq. (12)
  mpz_t e_inv, n_apos;
  mpz_inits(e_inv, n_apos, NULL);
  mpz_mul(n_apos, sk->p_apos, sk->q_apos); // n_apos = p'q'
  mpz_invert(e_inv, ppc->e, n_apos); // e_inv = e^-1 mod n'

  mpz_powm(ppc->A, Q, e_inv, pk->n);

  // 5. Generate random r < p'q'
  mpz_t r;
  mpz_init(r);
  mpz_set_ui(temp, 0);
  random_range(r, temp, n_apos);

  // 6. Compute A^ c' and s_e
  // page 5 Eq. (13) A^ = Q^r
  mpz_t A_caret;
  mpz_init(A_caret);
  mpz_powm(A_caret, Q, r, pk->n);

  // page 5 Eq. (14) c' = H(Q||A||A^||n1)
  sm3_mpzs(ppc->c_apos, Q, ppc->A, A_caret, ppc_prep->n1, NULL);

  // gmp_printf("assign:\nQ : %Zd\nA : %Zd\nA^: %Zd\nn1: %Zd\n",
  //	     Q, ppc->A, A_caret, ppc_prep->n1);

  // page 5 Eq. (15) s_e = r - c'e^-1
  mpz_mul(temp, ppc->c_apos, e_inv);
  mpz_mod(temp, temp, n_apos);
  mpz_sub(ppc->s_e, r, temp);
  mpz_mod(ppc->s_e, ppc->s_e, n_apos);

  // 7. Send the primary pre-credential to the Holder

  // clear all the temporary variables
  mpz_clears(temp, t, Q, e_inv, n_apos, r, A_caret, NULL);
}

/* int primary_pre_credential_verify */
/* (primary_pre_credential_t ppc, */
/*  issuer_pk_t pk, */
/*  mpz_t v_apos, */
/*  mpz_t n1, */
/*  mpz_t m1) */
/* { */
/*   int retval = 0; */
/*   mpz_t v, t, Q, A_caret; */
/*   mpz_inits(v, t, Q, A_caret, NULL); */

/*   do { */
/*     // 2. verify e is prime and satisfies Eq. (10) */
/*     if (!mpz_probab_prime_p(ppc->e, REPS_VAL)) { */
/*       gmp_printf("e is not prime: %Z", ppc->e); */
/*       retval = -1; */
/*       break; */
/*     } */

/*     mpz_set_ui(t, 0); */
/*     mpz_setbit(t,596); */
/*     if (mpz_cmp(ppc->e, t) < 0) { */
/*       gmp_printf("e < 2^596: %Zd\n", ppc->e); */
/*       retval = -1; */
/*       break; */
/*     } */

/*     mpz_setbit(t, 119); */
/*     if (mpz_cmp(t, ppc->e) < 0) { */
/*       gmp_printf("e > 2^596 + 2^119: %Zd\n", ppc->e); */
/*       retval = -1; */
/*       break; */
/*     } */

/*     // 3. Compute Q, page 5 Eq. (20) */
/*     mpz_add(v, v_apos, ppc->v_apos_apos); */
/*     mpz_powm(Q, pk->S, v, pk->n); */


/*     mpz_powm(t, pk->R_v + 0, m1, pk->n); */
/*     mpz_mul(Q, Q, t); */
/*     mpz_invert(Q, Q, pk->n); */
/*     mpz_mul(Q, pk->Z, Q); */
/*     mpz_mod(Q, Q, pk->n); */

/*     // 4. Vefiry Q = A^e */
/*     mpz_powm(t, ppc->A, ppc->e, pk->n); // A^e */
/*     if (mpz_cmp(Q, t)) { */
/*       gmp_printf("Q != A^e\n Q: %Zd\n e: %Zd\n", Q, ppc->e); */
/*       retval = -1; */
/*       break; */
/*     } */

/*     // 5. Compute A_caret */
/*     mpz_mul(t, ppc->s_e, ppc->e); */
/*     mpz_add(t, ppc->c_apos, t); */
/*     mpz_powm(A_caret, ppc->A, t, pk->n); */

/*     // 6. verify c' = H(Q||A||A^||n1) */
/*     sm3_mpzs(t, Q, ppc->A, A_caret, n1); */
/*     if (mpz_cmp(ppc->c_apos, t)) { */
/*       gmp_printf("c' != H(Q||A||A^||n1)\nc': %Zd\nH : %Zd\n", */
/*		 ppc->c_apos, t); */
/*       retval = -1; */
/*       break; */
/*     } */
/*   } while(0); */

/*   mpz_clears(v, t, Q, A_caret, NULL);   */
/*   return retval; */
/* } */
