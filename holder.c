#include "idemix_utils.h"
#include "idemix_crypto.h"
#include "idemix_holder.h"

#include <pbc/pbc.h>
#include "sm3.h"

// Chapter 5:

// 5.1 Holder Setup:

// prepares for primary credential
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
  // Eq. (5) page 4
  mpz_powm(ppc_prep->U, pk->S, v_apos, pk->n);
  mpz_powm(temp, pk->R_v[0], m1, pk->n);
  mpz_mul(ppc_prep->U, ppc_prep->U, temp);
  mpz_mod(ppc_prep->U, ppc_prep->U, pk->n);

  // 4. Compute Eq. (6) page 4
  mpz_t U_tilde;
  mpz_init(U_tilde);
  mpz_powm(U_tilde, pk->S, v_apos_tilde, pk->n);
  mpz_powm(temp, pk->R_v[0], m1_tilde, pk->n);
  mpz_mul(U_tilde, U_tilde, temp);
  mpz_mod(U_tilde, U_tilde, pk->n);

  //    Compute Eq. (7) page 4
  sm3_mpzs(ppc_prep->c, ppc_prep->U, U_tilde, n0);

  mpz_mul(temp, ppc_prep->c, v_apos);
  mpz_add(ppc_prep->v_apos_caret, v_apos_tilde, temp);

  //    Compute Eq. (8) page 4
  mpz_mul(temp, ppc_prep->c, m1);
  mpz_add(ppc_prep->m1_caret, m1_tilde, temp);

  // 5. Generate random 80-bit nonce n1
  random_num_exact_bits(ppc_prep->n1, 80);

  // 6. Send ppc_prep = { U, c, v'^, m1^, n1 } to the issuer

  // clear intermediate variables
  mpz_clears(m1_tilde, v_apos_tilde, temp, U_tilde);
}

// prepares for non-revokation credential
void issue_non_revok_pre_credential_prepare
(nr_pre_cred_prep_t nrpc_prep, // OUT
 element_t s_apos,
 nr_pk_t pk)
{
  element_random(s_apos);
  element_pow_zn(nrpc_prep->U, pk->h2, s_apos);
}

// end of 5.1

// 5.4 Storing Credentials:

int verify_primary_pre_credential(pri_pre_cred_t ppc,
				  iss_pk_t pk,
				  mpz_t v,  // = v' + v"
				  mpz_t n2, //
				  mpz_t m1)
{
  int retval = 0;
  mpz_t temp, Q, A_caret;
  mpz_inits(temp, Q, A_caret);

  // 2. verify e is prime and satisfies Eq. (10)
  if (!mpz_probab_prime_p(ppc->e, REPS_VAL)) {
    gmp_printf("e is not prime: %Z", ppc->e);
    return -1;
  }

  {
    mpz_set_ui(temp, 0);
    mpz_setbit(temp, 596);
    if (mpz_cmp(ppc->e, temp) < 0) {
      gmp_printf("e < 2^596: %Z", ppc->e);
      retval = -1;
    }
  }

  if (!retval) {
    mpz_setbit(temp, 119);
    if (mpz_cmp(temp, ppc->e) < 0) {
      gmp_printf("e > 2^596 + 2^119: %Z", ppc->e);
      retval = -1;
    }
  }

  if (!retval) {
    // 3. Compute Q, page 5 Eq. (20)
    mpz_powm(Q, pk->S, v, pk->n);
    mpz_powm(temp, pk->R_v[0], m1, pk->n);
    mpz_mul(Q, Q, temp);
    mpz_invert(Q, Q, pk->n);
    mpz_mul(Q, pk->Z, Q);
    mpz_mod(Q, Q, pk->n);

    // 4. Vefiry Q = A^e
    mpz_powm(temp, ppc->A, ppc->e, pk->n); // A^e
    if (mpz_cmp(Q, temp)) {
      gmp_printf("Q != A^e\n Q: %Z\n e: %Z", Q, ppc->e);
      retval = -1;
    }
  }

  if (!retval) {
    // 5. Compute A_caret
    mpz_mul(temp, ppc->s_e, ppc->e);
    mpz_add(temp, ppc->c_apos, temp);
    mpz_powm(A_caret, ppc->A, temp, pk->n);

    // 6. verify c' = H(Q||A||A^||n2)
    sm3_mpzs(temp, Q, ppc->A, A_caret, n2);
    if (mpz_cmp(ppc->c_apos, temp)) {
      gmp_printf("c' != H(Q||A||A^||n2)\nc': %Z\nH : %Z",
		 ppc->c_apos, temp);
      retval = -1;      
    }
  }

  mpz_clears(temp, Q);

  return retval;
}

void issue_primary_credential
(pri_cred_t pc, // OUT
 pri_pre_cred_t ppc,
 mpz_t v) // v_apos is generated in 5.1 - 1
{
  mpz_set(pc->A, ppc->A);
  mpz_set(pc->e, ppc->e);
  mpz_set(pc->v, v);
}

void issue_non_revok_credential
(nr_cred_t nrc, // OUT
 nr_pre_cred_t nrpc,
 element_t s_apos)
{
  element_set(nrc->IA, nrpc->IA);
  element_set(nrc->sigma, nrpc->sigma);
  element_set(nrc->c, nrpc->c);
  element_add(nrc->s, s_apos, nrpc->s_apos_apos);

  memcpy(nrc->wit_i, nrpc->wit_i, sizeof(witness_t));
  
  element_set(nrc->g_i, nrpc->g_i);
  element_set(nrc->g_apos_i, nrpc->g_apos_i);
  nrc->i = nrpc->i;
}

// end of 5.4

// end of Chapter 5
