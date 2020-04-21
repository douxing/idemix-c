#include <assert.h>
#include "idemix_primary_credential_response.h"
#include "idemix_random.h"

void primary_credential_response_init
(primary_credential_response_t pc_res,
 schema_t s)
{
  mpz_inits(pc_res->A,
            pc_res->e,
            pc_res->v_apos_apos,
            pc_res->s_e,
            pc_res->c_apos,
            NULL);
  attr_vec_init(pc_res->Ak, schema_attr_cnt_known(s));
}

void primary_credential_response_clear
(primary_credential_response_t pc_res)
{
  mpz_clears(pc_res->A,
             pc_res->e,
             pc_res->v_apos_apos,
             pc_res->s_e,
             pc_res->c_apos,
             NULL);
  attr_vec_clear(pc_res->Ak);
}

void primary_credential_response_assign
(primary_credential_response_t pc_res,
 issuer_pk_t pk,
 issuer_sk_t sk,
 attr_vec_t Ak,
 primary_credential_request_t pc_req)
{
  // temporary variables;
  mpz_t temp, t;
  mpz_inits(temp, t, NULL);

  // Issuer prepare the credential:
  // 1. Compute m2 <- H(i||H_cop)
  //    done by caller, in schema

  // 2. set attributes from Ak
  attr_vec_set(pc_res->Ak, Ak);

  // 3. Generate random 2724-bit number v" with most significant bit equal 1
  //    and random prime e such that 2^596 <= e <= 2^596 + 2^119
  random_num_exact_bits(pc_res->v_apos_apos, 2724);

  // page 5 Eq. (10)
  mpz_set_ui(temp, 0);
  mpz_setbit(temp, 596); // low bound
  mpz_set(t, temp);
  mpz_setbit(t, 119);
  mpz_add_ui(t, t, 1);  // high bound
  random_prime_range(pc_res->e, temp, t);

  // 4 Compute Q Eq. (11) page 5
  mpz_t Q;
  mpz_init_set(Q, pc_req->U);
  mpz_powm(temp, pk->S, pc_res->v_apos_apos, pk->n);
  mpz_mul(Q, Q, temp);
  mpz_mod(Q, Q, pk->n);
  for (unsigned long i = 0; i < attr_vec_size(pc_res->Ak); ++i) {
    attr_ptr mi_p = attr_vec_head(pc_res->Ak) + i;
    mpz_powm(temp, pk->R_v + mi_p->i, mi_p->v, pk->n);
    mpz_mul(Q, Q, temp);
    mpz_mod(Q, Q, pk->n);
  }
  mpz_invert(Q, Q, pk->n);
  mpz_mul(Q, pk->Z, Q);
  mpz_mod(Q, Q, pk->n);

  // gmp_printf("Q(11): %Zd\n", Q);

  // page 5 Eq. (12)
  mpz_t e_inv, n_apos;
  mpz_inits(e_inv, n_apos, NULL);
  mpz_mul(n_apos, sk->p_apos, sk->q_apos); // n_apos = p'q'
  mpz_invert(e_inv, pc_res->e, n_apos); // e_inv = e^-1 mod n'

  mpz_powm(pc_res->A, Q, e_inv, pk->n);

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
  sm3_mpzs(pc_res->c_apos, Q, pc_res->A, A_caret, pc_req->n1, NULL);

  // gmp_printf("assign:\nQ : %Zd\nA : %Zd\nA^: %Zd\nn1: %Zd\n",
  //	     Q, pc_res->A, A_caret, pc_req->n1);

  // page 5 Eq. (15) s_e = r - c'e^-1
  mpz_mul(temp, pc_res->c_apos, e_inv);
  mpz_mod(temp, temp, n_apos);
  mpz_sub(pc_res->s_e, r, temp);
  mpz_mod(pc_res->s_e, pc_res->s_e, n_apos);

  // 7. Send the primary pre-credential to the Holder

  // clear all the temporary variables
  mpz_clears(temp, t, Q, e_inv, n_apos, r, A_caret, NULL);
}
