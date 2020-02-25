#include "idemix_utils.h"
#include "idemix_issuer.h"
#include "idemix_holder.h"

#include <pbc/pbc.h>
#include "sm3.h"

// 5.1 Holder Setup - prepares for primary credential
// m1: currently, only m1(link secret) is needed
void prepare_primary_credential(issuer_pk_t pk, mpz_t m1, mpz_t n0,
				pre_prim_cred_t ppc) {
  mpz_inits(ppc->U, ppc->v_apos_caret, ppc->m1_caret, ppc->n1);
  
  // no hidden attributes to set, except m1: link secret
  // 1. Generate random 2128-bit v'
  mpz_t v_apos;
  mpz_inits(v_apos);
  
  // 2. Generate random 593-bit mi~ in Ah and random 673-bit v'~
  mpz_t m1_tilde, v_apos_tilde;
  mpz_inits(m1_tilde, v_apos_tilde);
  random_num_exact_bits(m1_tilde, 593);
  random_num_exact_bits(v_apos_tilde, 673);

  mpz_t U_tilde, temp;
  mpz_inits(U_tilde, temp);
  // 3. Compute(U) taking S, Z, Ri from Pk(public key of issuer)
  // formular (5) page 4
  mpz_powm(ppc->U, pk->S, v_apos, pk->n);
  mpz_powm(temp, pk->R_v[0], m1, pk->n);
  mpz_mul(ppc->U, ppc->U, temp);
  mpz_mod(ppc->U, ppc->U, pk->n);

  // 4. Compute formular (6) page 4
  mpz_powm(U_tilde, pk->S, v_apos_tilde, pk->n);
  mpz_powm(temp, pk->R_v[0], m1_tilde, pk->n);
  mpz_mul(U_tilde, U_tilde, temp);
  mpz_mod(U_tilde, U_tilde, pk->n);

  //    Compute formular (7) page 4
  char buf[BUF_SIZE] = { 0 };
  char c[SM3_DIGEST_LENGTH] = { 0 };
  size_t count;
  sm3_ctx_t ctx;
  sm3_init(&ctx);
  mpz_export(buf, &count, 1, 1, 1, 0, ppc->U);
  sm3_update(&ctx, buf, count);
  mpz_export(buf, &count, 1, 1, 1, 0, U_tilde);
  sm3_update(&ctx, buf, count);
  mpz_export(buf, &count, 1, 1, 1, 0, n0);
  sm3_update(&ctx, buf, count);
  sm3_final(&ctx, c);
  mpz_import(ppc->c, SM3_DIGEST_LENGTH, 1, 1, 1, 0, c);

  mpz_mul(temp, ppc->c, v_apos);
  mpz_add(ppc->v_apos_caret, v_apos_tilde, temp);

  //    Compute formular (8) page 4
  mpz_mul(temp, ppc->c, m1);
  mpz_add(ppc->m1_caret, m1_tilde, temp);

  // 5. Generate random 80-bit nonce n1
  random_num_exact_bits(ppc->n1, 80);

  // 6. Send ppc = { U, c, v'^, m1^, n1 } to the issuer
}

// 5.1 Holder Setup - prepares for non-revokation credential
void prepare_non_revokation_credential(pairing_t pairing, revok_pk_t pk, pre_nonrev_cred_t pnrc)
{
  element_t s_apos;
  element_init_Zr(s_apos, pairing);
  element_random(s_apos);
  element_pow_zn(pnrc->U, pk->h2, s_apos);
}
