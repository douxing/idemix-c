#include <stdlib.h>
#include <gmp.h>
#include "idemix_utils.h"
#include "idemix_accumulator.h"
#include "idemix_schema.h"
#include "idemix_issuer.h"
#include "idemix_holder.h"

// section 4.2 Primary Credential Cryptographic setup
void issuer_keys_setup(unsigned long L, issuer_pk_t pk, issuer_sk_t sk)
{
  mpz_inits(pk->n, pk->S, pk->Z);
  mpz_inits(sk->p_apos, sk->q_apos, sk->p, sk->q);

  // init temporary variables
  mpz_t x, min, max;
  mpz_inits(x, min, max);

  // 1. Random 1024-bit primes p',q'
  // such thatp = 2p'+ 1 and q = 2q'+ 1 are primes too.
  // Then compute n = pq.
  // generate p' and p
  do {
    random_prime_exact_bits(sk->p_apos, 1024);
    mpz_mul_ui(sk->p, sk->p_apos, 2);
    mpz_add_ui(sk->p, sk->p, 1);
  } while(mpz_probab_prime_p(sk->p, REPS_VAL));

  // generate q' and q
  do {
    random_prime_exact_bits(sk->q_apos, 1024);
    mpz_mul_ui(sk->q, sk->q_apos, 2);
    mpz_add_ui(sk->q, sk->q, 1);
  } while(mpz_probab_prime_p(sk->q, REPS_VAL));

  // n = pq (should be at least 2049 bits > 2048bits)
  mpz_mul(pk->n, sk->p, sk->q);

  // 2. A random quadratic residue S modulo n
  random_num_exact_bits(x, 1024);
  mpz_powm_ui(pk->S, x, 2, pk->n); // no need to mod, at most 2048 bits
  // no need to check mpz_sizeinbase(pk->S, 2) < 2048);

  // 3. Random xZ, xR1, ..., xRl in range [2, p'q' - 1]
  // set sk->xZ and pk->Z
  mpz_set_ui(min, 2);
  mpz_mul(max, sk->p_apos, sk->q_apos);
  random_range(sk->xZ, min, max);
  mpz_powm(pk->Z, pk->S, sk->xZ, pk->n);

  // set xRi and Ri, formular (1) in paper
  sk->xR_c = pk->R_c = L;
  sk->xR_v = (mpz_t *)malloc(sizeof(mpz_t) * L);
  pk->R_v  = (mpz_t *)malloc(sizeof(mpz_t) * L);

  for (unsigned long i = 0; i < L; ++i) {
    mpz_inits(sk->xR_v[i], pk->R_v[i]);
    random_range(sk->xR_v[i], min, max);
    mpz_powm(pk->R_v[i], pk->S, sk->xR_v[i], pk->n);
  }
}

// section 4.4 Non-revokation Credential Cryptographic setup
// pairing: pairing parameter
// g      : the generator of G1
// g_apos : the generator of G2
// pk, sk : to be initialized element
void nonrev_keys_setup(pairing_t pairing,
		       element_t g, element_t _g_apos,
		       nonrev_pk_t pk, nonrev_sk_t sk)
{
  (void)_g_apos;

  // init secret key
  element_init_Zr(sk->x, pairing);
  element_init_Zr(sk->sk, pairing);
  element_random(sk->x);
  element_random(sk->sk);

  // init public key
  element_init_G1(pk->h, pairing);
  element_init_G1(pk->h0, pairing);
  element_init_G1(pk->h1, pairing);
  element_init_G1(pk->h2, pairing);
  element_init_G1(pk->h_tilde, pairing);
  element_random(pk->h);
  element_random(pk->h0);
  element_random(pk->h1);
  element_random(pk->h2);
  element_random(pk->h_tilde);

  element_init_G2(pk->u, pairing);
  element_init_G2(pk->h_caret, pairing);
  element_random(pk->u);
  element_random(pk->h_caret);

  element_init_G1(pk->pk, pairing);
  element_init_G2(pk->y, pairing);
  element_pow_zn(pk->pk, g, sk->sk);
  element_pow_zn(pk->y, pk->h_caret, sk->x);
}

void compute_m2(mpz_t m2, mpz_t i, mpz_t H_cop) {
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

// 5.2 Primary Credential Issurance
int issue_primary_pre_credential(issuer_pk_t pk,
				 issuer_sk_t sk,
				 prim_pre_cred_prep_t ppc_prep,
				 prim_pre_cred_t ppc,
				 schema_t schema,
				 mpz_t n0,
				 accumulator_t acc)
{
  // assert index < acc->L
  // assert schema->attr_c == pk->R_c == sk->xR_c
  // assert schema->attr_v[0].is_hidden = 1
  // assert schema->attr_v[1].is_hidden = 0
  // assert schema->attr_v[2].is_hidden = 1
  // assert schema->attr_v[2].m = 0 // currently ZERO

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

  // 2. verify c = H(U||U_caret||n0)
  unsigned char buf[BUF_SIZE] = { 0 };
  unsigned char c[SM3_DIGEST_LENGTH] = { 0 };
  size_t count;
  sm3_ctx_t ctx;
  sm3_init(&ctx);
  mpz_export(buf, &count, 1, 1, 1, 0, ppc_prep->U);
  sm3_update(&ctx, buf, count);
  mpz_export(buf, &count, 1, 1, 1, 0, U_caret);
  sm3_update(&ctx, buf, count);
  mpz_export(buf, &count, 1, 1, 1, 0, n0);
  sm3_update(&ctx, buf, count);
  sm3_final(&ctx, c);
  mpz_import(temp, SM3_DIGEST_LENGTH, 1, 1, 1, 0, c); // temp = c
  int res = mpz_cmp(ppc_prep->c, temp);
  if (res != 0) {
    gmp_printf("hash differs, \nc(U) : %Z\nc(U^): %Z\n");
    return -1;
  }

  // 3. Verify the length of v'^, m1^
  // ... ignore ...
  mpz_inits(ppc->A, ppc->v_apos_apos, ppc->e, ppc->s_e, ppc->c_apos);

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
  mpz_setbit(temp, 596);
  mpz_add(ppc->e, temp, ppc->e);

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

  // temporary variables
  mpz_t e_inv, n_apos;
  mpz_inits(e_inv, n_apos);
  mpz_mul(n_apos, sk->p_apos, sk->q_apos); // n_apos = p'q'
  mpz_invert(e_inv, ppc->e, n_apos); // e_inv = e^-1 mod n'

  // page 5 formular (12)
  mpz_powm(ppc->A, Q, e_inv, pk->n);

  // 5. Generate random r < p'q'
  mpz_t r;
  mpz_init(r);
  mpz_set_ui(temp, 0);
  random_range(r, temp, n_apos);

  // 6. Compute A^ c' and s_e
  // page 5 formular (13)
  mpz_t A_caret;
  mpz_init(A_caret);
  mpz_powm(A_caret, Q, r, pk->n);

  // page 5 formular (14)
  sm3_init(&ctx);
  mpz_export(buf, &count, 1, 1, 1, 0, Q);
  sm3_update(&ctx, buf, count);
  mpz_export(buf, &count, 1, 1, 1, 0, ppc->A);
  sm3_update(&ctx, buf, count);
  mpz_export(buf, &count, 1, 1, 1, 0, A_caret);
  sm3_update(&ctx, buf, count);
  mpz_export(buf, &count, 1, 1, 1, 0, ppc_prep->n1);
  sm3_update(&ctx, buf, count);
  sm3_final(&ctx, c);
  mpz_import(ppc->c_apos, SM3_DIGEST_LENGTH, 1, 1, 1, 0, c);

  // page 5 formular (15)
  mpz_mul(temp, ppc->c_apos, e_inv);
  mpz_mod(temp, temp, n_apos);
  mpz_sub(ppc->s_e, r, temp);
  mpz_mod(ppc->s_e, ppc->s_e, n_apos);
  
  // 7. Send the primary pre-credential to the Holder
 
  return 0;
}

// 5.3 Non-revocation Credential Issuance
int issue_non_revokation_pre_credential(nonrev_pre_cred_t nrpc,           // issuer -> holder
					pairing_t pairing,
					nonrev_pk_t pk,
					nonrev_sk_t sk,
					nonrev_pre_cred_prep_t nrpc_prep, // holder -> issuer
					schema_t schema,
					accumulator_t acc,
					unsigned long i,
					accum_pk_t accum_pk,
					accum_sk_t accum_sk)
{
  // initialized pairing members
  element_init_GT(nrpc->IA, pairing);
  element_init_G1(nrpc->sigma, pairing);
  element_init_Zr(nrpc->c, pairing);
  element_init_Zr(nrpc->s_apos_apos, pairing);

  element_init_G1(nrpc->sigma_i, pairing);
  element_init_G2(nrpc->u_i, pairing);
  element_init_G2(nrpc->omega, pairing);
  
  element_init_G1(nrpc->g_i, pairing);
  element_init_G2(nrpc->g_apos_i, pairing);

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
  element_clear(pow);

  compute_omega(nrpc->omega, acc, i);
  
  // page 5 formular (17)

  element_clear(A);
  return 0;
}
