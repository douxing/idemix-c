#include "idemix_bitmap.h"
#include "idemix_crypto.h"
#include "idemix_random.h"
#include "idemix_issuer.h"

#include <stdlib.h>
#include <gmp.h>

// Chapter 5:

// 5.2 Primary Credential Issurance

// call this function before 'primary_pre_credential_init'
int verify_primary_pre_credential_prepare
(primary_pre_credential_prepare_t ppc_prep,
 issuer_pk_t pk,
 mpz_t n0)
{
  unsigned long l = attr_vec_size(ppc_prep->m_carets);
  int retval = 0;

  // Issuer verifies the corretness of Holder's input:
  mpz_t U_caret, temp;
  mpz_inits(U_caret, temp);

  // 1. Compute U_caret
  // page 4 Eq. (9)
  mpz_invert(U_caret, ppc_prep->U, pk->n);
  mpz_powm(U_caret, U_caret, ppc_prep->c, pk->n);
  for (unsigned long i = 0; i < l; ++i) {
    attr_ptr mi_caret = attr_vec_head(ppc_prep->m_carets) + i;
    mpz_powm(temp, pk->R_v[mi_caret->i], mi_caret->v, pk->n);
    mpz_mul(U_caret, U_caret, temp);
  }
  mpz_powm(temp, pk->S, ppc_prep->v_apos_caret, pk->n);
  mpz_mul(U_caret, U_caret, temp);

  // 2. verify h = H(U||U_caret||n0)
  sm3_mpzs(temp, ppc_prep->U, U_caret, n0); // temp = h
  if (mpz_cmp(ppc_prep->c, temp)) {
    gmp_printf("hash differs, \nc with U : %Z\nc with U^: %Z\n",
	       ppc_prep->c, temp);
    
    retval = -1;
  }

  // TODO:
  // 3. verify that v'^ is 673-bit number
  //    mi are 594-bit number

  mpz_clears(U_caret, temp);
  return retval;
}

void issue_primary_pre_credential
(primary_pre_credential_t ppc, // OUT, known attributes already set in schema
 issuer_sk_t sk,
 issuer_pk_t pk,
 mpz_t U,  // from primary_pre_credential_prepare
 mpz_t n1) // from primary_pre_credential_prepare
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
  // page 5 Eq. (10)
  random_num_exact_bits(ppc->v_apos_apos, 2724);

  mpz_set_ui(temp, 0);
  mpz_set_ui(ppc->e, 0);
  mpz_setbit(ppc->e, 119);
  mpz_add_ui(ppc->e, ppc->e, 1);
  random_range(ppc->e, temp, ppc->e);
  mpz_setbit(ppc->e, 596); // ppc->e += 2^596

  // 4 Compute Q Eq. (11) page 5
  mpz_t Q;
  mpz_init_set(Q, U);
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
  sm3_mpzs(ppc->c_apos, Q, ppc->A, A_caret, n1);

  // page 5 Eq. (15) s_e = r - c'e^-1
  mpz_mul(temp, ppc->c_apos, e_inv);
  mpz_mod(temp, temp, n_apos);
  mpz_sub(ppc->s_e, r, temp);
  mpz_mod(ppc->s_e, ppc->s_e, n_apos);
  
  // 7. Send the primary pre-credential to the Holder

  // clear all the temporary variables
  mpz_clears(temp, Q, e_inv, n_apos, r, A_caret);
}

// 5.3 Non-revocation Credential Issuance

void issue_nonrev_pre_credential
(nonrev_pre_credential_t nrpc, // OUT to holder
 accumulator_t acc, // OUT to ledger
 nonrev_pre_credential_prepare_t nrpc_prep,
 pairing_t pairing,
 nonrev_pk_t pk,
 nonrev_sk_t sk,
 mpz_t m2,
 unsigned long i,
 accumulator_pk_t acc_pk,
 accumulator_sk_t acc_sk)
{
  mpz_t mpz_i;
  mpz_init(mpz_i);
  mpz_set_ui(mpz_i, i);
  
  // 1. Generate random numbers s", c mod q.
  element_random(nrpc->s_apos_apos);
  element_random(nrpc->c);

  // 2. Take m2 from the primary credential he is preparing for Holder
  //    set by the caller

  // 3. Take A as the accumulator value for which index i was taken.
  //    Retrieve current set of non-revoked indices V.
  // no need to Take A as temporary variable
  // V is in accumulator
  
  // 4. Compute
  // page 5 Eq. (16)
  element_t temp;
  element_init_Zr(temp, pairing);
  element_set_mpz(temp, m2);
  element_pow2_zn(nrpc->sigma, pk->h1, temp, pk->h2, nrpc->s_apos_apos);
  element_mul(nrpc->sigma, nrpc->sigma, pk->h0);
  element_mul(nrpc->sigma, nrpc->sigma, nrpc_prep->U);
  element_mul(nrpc->sigma, nrpc->sigma, acc->g1_v[i]);

  element_add(temp, sk->x, nrpc->c);
  element_invert(temp, temp);
  element_pow_zn(nrpc->sigma, nrpc->sigma, temp);

  compute_w(nrpc->wit_i->w, acc, i);
  
  // page 5 Eq. (17)
  element_pow_mpz(temp, acc_sk->gamma, mpz_i); // temp = gamma^i
  element_pow_zn(nrpc->wit_i->u_i, pk->u, temp); // u_i
  
  element_add(temp, sk->sk, temp); // temp = sk + gamma^i
  element_invert(temp, temp);      // temp = 1 / (sk + gamma^i)
  element_pow_zn(nrpc->wit_i->sigma_i, acc->g_apos, temp); // sigma_i

  // page 5 Eq. (18)
  element_mul(acc->acc, acc->acc, acc->g2_v[acc->L - i]); // A
  bitmap_setbit(acc->V, i); // V

  // page 5 Eq. (19)
  // already set: sigma_i, u_i, w
  element_set(nrpc->wit_i->g_i, acc->g1_v[i]);
  bitmap_set(nrpc->wit_i->V, acc->V);

  // set the rest members in non-revocation pre-credential
  element_set(nrpc->IA, acc_pk->z);
  element_set(nrpc->g_i, acc->g1_v[i]);
  element_set(nrpc->g_apos_i, acc->g2_v[i]);
  nrpc->i = i;
  
  element_clear(temp);
  mpz_clear(mpz_i);
}

// end of 5.3

// end of Chapter 5

// Chapter 6

void revoke_index(accumulator_t acc, // OUT
		  const unsigned long index)
{
  // 1. Set V = V\{i}
  bitmap_clrbit(acc->V, index);
  
  // 2. Compute A = A/g'_(L+1-i)
  element_t temp;
  element_init(temp, acc->acc->field);
  element_invert(temp, acc->g2_v[acc->L - index]);
  element_mul(acc->acc, acc->acc, temp);
  element_clear(temp);

  // Publish {V, A}
}

// end of Chapter 6
