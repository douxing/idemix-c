#include "idemix_utils.h"
#include "idemix_schema.h"
#include "idemix_crypto.h"
#include "idemix_credentials.h"
#include "idemix_issuer.h"

#include <stdlib.h>
#include <gmp.h>

// Chapter 5:

// 5.2 Primary Credential Issurance

// call this function before 'primary_pre_credential_init'
int verify_primary_pre_credential_prepare(
  pri_pre_cred_prep_t ppc_prep,
  iss_pk_t pk,
  mpz_t n0
) {
  int retval = 0;
  // Issuer verifies the corretness of Holder's input:
  mpz_t U_caret, temp;
  mpz_inits(U_caret, temp);

  // 1. Compute U_caret
  // page 4 formular (9)
  mpz_invert(U_caret, ppc_prep->U, pk->n);
  mpz_powm(U_caret, U_caret, ppc_prep->c, pk->n);
  mpz_powm(temp, pk->R_v[0], ppc_prep->m1_caret, pk->n);
  mpz_mul(U_caret, U_caret, temp);
  mpz_powm(temp, pk->S, ppc_prep->v_apos_caret, pk->n);
  mpz_mul(U_caret, U_caret, temp);

  // 2. verify h = H(U||U_caret||n0)
  sm3_mpzs(temp, ppc_prep->U, U_caret, n0); // temp = h
  if (mpz_cmp(ppc_prep->c, temp)) {
    gmp_printf("hash differs, \nc with U : %Z\nc with U^: %Z\n",
	       ppc_prep->c, temp);
    
    retval = -1;
  }

  mpz_clears(U_caret, temp);
  return retval;
}

void issue_primary_pre_credential
(pri_pre_cred_t ppc, // OUT
 pri_pre_cred_prep_t ppc_prep,
 iss_sk_t sk,
 iss_pk_t pk,
 schema_t schema)
{
  // assert index < acc->L
  // assert schema->attr_c == pk->R_c == sk->xR_c
  // assert schema->attr_v[0].is_hidden = 1
  // assert schema->attr_v[1].is_hidden = 0
  // assert schema->attr_v[2].is_hidden = 1
  // assert schema->attr_v[2].m = 0 // currently ZERO

  // temporary variables;
  mpz_t temp;
  mpz_init(temp);

  // 3. Verify the length of v'^, m1^
  // ... ignore ...

  // Issuer prepare the credential:
  // 1. Compute m2 <- H(i||H_cop)
  //    already okay, in schema

  // 2. set attributes from Ak
  //    already okay, in schema

  // 3. Generate random 2724-bit number v" with most significant bit equal 1
  //    and random prime e such that 2^596 <= e <= 2^596 + 2^119
  // page 5 formular (10)
  random_num_exact_bits(ppc->v_apos_apos, 2724);

  mpz_set_ui(temp, 0);
  mpz_set_ui(ppc->e, 0);
  mpz_setbit(ppc->e, 119);
  mpz_add_ui(ppc->e, ppc->e, 1);
  random_range(ppc->e, temp, ppc->e);
  mpz_setbit(ppc->e, 596); // ppc->e += 2^596

  // 4 Compute Q
  // page 5 formular (11)
  mpz_t Q;
  mpz_init(Q);
  mpz_set(Q, ppc_prep->U);
  mpz_powm(temp, pk->S, ppc->v_apos_apos, pk->n);
  mpz_mul(Q, Q, temp);
  mpz_mod(Q, Q, pk->n);
  // handle m2, ignore m1 and m3
  mpz_powm(temp, pk->R_v[1], schema->attr_v[1].m, pk->n);
  mpz_mul(Q, Q, temp);
  mpz_mod(Q, Q, pk->n);
  for (unsigned long i = 3; i < schema->attr_c; ++i) {
    if (schema->attr_v[i].is_hidden || !mpz_sgn(schema->attr_v[i].m)) {
      continue;
    }

    // not hidden and mi != zero
    mpz_powm(temp, pk->R_v[i], schema->attr_v[i].m, pk->n);
    mpz_mul(Q, Q, temp);
    mpz_mod(Q, Q, pk->n);
  }
  mpz_invert(Q, Q, pk->n);
  mpz_mul(Q, pk->Z, Q);
  mpz_mod(Q, Q, pk->n);

  // page 5 formular (12)
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
  // page 5 formular (13) A^ = Q^r
  mpz_t A_caret;
  mpz_init(A_caret);
  mpz_powm(A_caret, Q, r, pk->n);

  // page 5 formular (14) c' = H(Q||A||A^||n1)
  sm3_mpzs(ppc->c_apos, Q, ppc->A, A_caret, ppc_prep->n1);

  // page 5 formular (15) s_e = r - c'e^-1
  mpz_mul(temp, ppc->c_apos, e_inv);
  mpz_mod(temp, temp, n_apos);
  mpz_sub(ppc->s_e, r, temp);
  mpz_mod(ppc->s_e, ppc->s_e, n_apos);
  
  // 7. Send the primary pre-credential to the Holder

  // clear all the temporary variables
  mpz_clears(temp, Q, e_inv, n_apos, r, A_caret);
}

// 5.3 Non-revocation Credential Issuance

void compute_m2(mpz_t m2,
		const mpz_t i,
		const mpz_t H_cop)
{
  unsigned char buf[BUF_SIZE] = { 0 };
  unsigned char h[SM3_DIGEST_LENGTH] = { 0 };
  size_t count;
  sm3_ctx_t ctx;

  sm3_init(&ctx);
  mpz_export(buf, &count, 1, 1, 1, 0, i);
  sm3_update(&ctx, buf, count);
  mpz_export(buf, &count, 1, 1, 1, 0, H_cop);
  sm3_update(&ctx, buf, count);
  sm3_final(&ctx, h);
  mpz_import(m2, SM3_DIGEST_LENGTH, 1, 1, 1, 0, h); // set m2
}

void issue_non_revok_pre_credential
(nr_pre_cred_t nrpc, // OUT to holder
 nr_pre_cred_prep_t nrpc_prep,
 pairing_t pairing,
 nr_pk_t pk,
 nr_sk_t sk,
 schema_t schema,
 accumulator_t acc,
 unsigned long i,
 accum_pk_t accum_pk,
 accum_sk_t accum_sk)
{
  // 1. Generate random numbers s", c mod q.
  element_random(nrpc->s_apos_apos);
  element_random(nrpc->c);

  // 2. Take m2 from the primary credential he is preparing for Holder
  element_t m2;
  element_init_Zr(m2, pairing);
  element_set_mpz(m2, schema->attr_v[1].m);

  // 3. Take A as the accumulator value for which index i was taken.
  //    Retrieve current set of non-revoked indices V.
  element_t A;
  element_init_G2(A, pairing);
  element_set(A, acc->acc);

  // V is in accumulator
  
  // 4. Compute
  // page 5 formular (16)
  element_pow2_zn(nrpc->sigma, pk->h1, m2, pk->h2, nrpc->s_apos_apos);
  element_mul(nrpc->sigma, nrpc->sigma, pk->h0);
  element_mul(nrpc->sigma, nrpc->sigma, nrpc_prep->U);
  element_mul(nrpc->sigma, nrpc->sigma, acc->g1_v[i]);
  element_t pow;
  element_init_Zr(pow, pairing);
  element_add(pow, sk->x, nrpc->c);
  element_invert(pow, pow);
  element_pow_zn(nrpc->sigma, nrpc->sigma, pow);

  compute_omega(nrpc->omega, acc, i);
  
  // page 5 formular (17)

  element_clear(pow);
  element_clear(A);
  element_clear(m2);
}

// end of 5.3
