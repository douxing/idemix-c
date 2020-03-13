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
	    ppc->c_apos);
  attr_vec_init(ppc->Ak, schema_attr_cnt_known(s));
}

void primary_pre_credential_clear
(primary_pre_credential_t ppc)
{
  mpz_clears(ppc->A,
	     ppc->e,
	     ppc->v_apos_apos,
	     ppc->s_e,
	     ppc->c_apos);
  attr_vec_clear(ppc->Ak);
}

void primary_pre_credential_assign
(primary_pre_credential_t ppc,
 issuer_pk_t pk,
 issuer_sk_t sk,
 primary_pre_credential_prepare_t ppc_prep)
{
  // temporary variables;
  mpz_t temp;
  mpz_init(temp);

  // Issuer prepare the credential:
  // 1. Compute m2 <- H(i||H_cop)
  //    done by caller, in schema

  // 2. set attributes from Ak
  //    done by caller, in schema

  // 3. Generate random 2724-bit number v" with most significant bit equal 1
  //    and random prime e such that 2^596 <= e <= 2^596 + 2^119
  random_num_exact_bits(ppc->v_apos_apos, 2724);

  // page 5 Eq. (10)
  mpz_set_ui(temp, 0); 
  mpz_set_ui(ppc->e, 0);
  mpz_setbit(ppc->e, 119);
  mpz_add_ui(ppc->e, ppc->e, 1);
  random_range(ppc->e, temp, ppc->e);
  mpz_setbit(ppc->e, 596); // ppc->e += 2^596

  // 4 Compute Q Eq. (11) page 5
  mpz_t Q;
  mpz_init_set(Q, ppc_prep->U);
  mpz_powm(temp, pk->S, ppc->v_apos_apos, pk->n);
  mpz_mul(Q, Q, temp);
  mpz_mod(Q, Q, pk->n);
  for (unsigned long i = 0; i < attr_vec_size(ppc->Ak); ++i) {
    attr_ptr mi_p = attr_vec_head(ppc->Ak) + i;
    mpz_powm(temp, pk->R_v[mi_p->i], mi_p->v, pk->n);
    mpz_mul(Q, Q, temp);
    mpz_mod(Q, Q, pk->n);
  }
  mpz_invert(Q, Q, pk->n);
  mpz_mul(Q, pk->Z, Q);
  mpz_mod(Q, Q, pk->n);

  // page 5 Eq. (12)
  mpz_t e_inv, n_apos;
  mpz_inits(e_inv, n_apos);
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
  sm3_mpzs(ppc->c_apos, Q, ppc->A, A_caret, ppc_prep->n1);

  // page 5 Eq. (15) s_e = r - c'e^-1
  mpz_mul(temp, ppc->c_apos, e_inv);
  mpz_mod(temp, temp, n_apos);
  mpz_sub(ppc->s_e, r, temp);
  mpz_mod(ppc->s_e, ppc->s_e, n_apos);
  
  // 7. Send the primary pre-credential to the Holder

  // clear all the temporary variables
  mpz_clears(temp, Q, e_inv, n_apos, r, A_caret);
}
