#include "idemix_utils.h"
#include "idemix_crypto.h"
#include "idemix_holder.h"

#include <pbc/pbc.h>
#include "sm3.h"

// 5.1 Holder Setup - prepares for primary credential
// m1: currently, only m1(link secret) is needed
void issue_primary_pre_credential_prepare
(pri_pre_cred_prep_t ppc_prep, // OUT
				    mpz_t v_apos, // OUT for Holder itself
				    iss_pk_t pk,
				    mpz_t m1, // link secret
				    mpz_t n0)
{
  // no hidden attributes to set, except m1: link secret
  // 1. Generate random 2128-bit v'
  random_num_exact_bits(v_apos, 2128);
  
  // 2. Generate random 593-bit mi~ in Ah and random 673-bit v'~
  mpz_t m1_tilde, v_apos_tilde;
  mpz_inits(m1_tilde, v_apos_tilde);
  random_num_exact_bits(m1_tilde, 593);
  random_num_exact_bits(v_apos_tilde, 673);

  mpz_t temp;
  mpz_init(temp);
  // 3. Compute(U) taking S, Z, Ri from Pk(public key of issuer)
  // formular (5) page 4
  mpz_powm(ppc_prep->U, pk->S, v_apos, pk->n);
  mpz_powm(temp, pk->R_v[0], m1, pk->n);
  mpz_mul(ppc_prep->U, ppc_prep->U, temp);
  mpz_mod(ppc_prep->U, ppc_prep->U, pk->n);

  // 4. Compute formular (6) page 4
  mpz_t U_tilde;
  mpz_init(U_tilde);
  mpz_powm(U_tilde, pk->S, v_apos_tilde, pk->n);
  mpz_powm(temp, pk->R_v[0], m1_tilde, pk->n);
  mpz_mul(U_tilde, U_tilde, temp);
  mpz_mod(U_tilde, U_tilde, pk->n);

  //    Compute formular (7) page 4
  sm3_mpzs(ppc_prep->c, ppc_prep->U, U_tilde, n0);

  mpz_mul(temp, ppc_prep->c, v_apos);
  mpz_add(ppc_prep->v_apos_caret, v_apos_tilde, temp);

  //    Compute formular (8) page 4
  mpz_mul(temp, ppc_prep->c, m1);
  mpz_add(ppc_prep->m1_caret, m1_tilde, temp);

  // 5. Generate random 80-bit nonce n1
  random_num_exact_bits(ppc_prep->n1, 80);

  // 6. Send ppc_prep = { U, c, v'^, m1^, n1 } to the issuer

  // clear intermediate variables
  mpz_clears(m1_tilde, v_apos_tilde, temp, U_tilde);
}

// 5.1 Holder Setup - prepares for non-revokation credential
void issue_non_revok_pre_credential_prepare
(nr_pre_cred_prep_t nrpc_prep, // OUT
 pairing_t pairing,
 nr_pk_t pk)
{
  element_t s_apos; // s'_R
  element_init_Zr(s_apos, pairing);
  element_random(s_apos);
  element_pow_zn(nrpc_prep->U, pk->h2, s_apos);
  element_clear(s_apos);
}
