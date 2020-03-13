#include "idemix_non_revocation_pre_credential.h"

void nonrev_pre_credential_init(nonrev_pre_credential_t nrpc, // OUT
				pairing_t pairing)
{
  // initialized pairing members
  element_init_GT(nrpc->IA, pairing);
  element_init_G1(nrpc->sigma, pairing);
  element_init_Zr(nrpc->c, pairing);
  element_init_Zr(nrpc->s_apos_apos, pairing);

  witness_init(nrpc->wit_i, pairing);

  element_init_G1(nrpc->g_i, pairing);
  element_init_G2(nrpc->g_apos_i, pairing);
}

void nonrev_pre_credential_clear
(nonrev_pre_credential_t nrpc)
{
  // initialized pairing members
  element_clear(nrpc->IA);
  element_clear(nrpc->sigma);
  element_clear(nrpc->c);
  element_clear(nrpc->s_apos_apos);

  witness_clear(nrpc->wit_i);

  element_clear(nrpc->g_i);
  element_clear(nrpc->g_apos_i);
}

void nonrev_pre_credential_assign
(nonrev_pre_credential_t nrpc,
 mpz_t m2,
 unsigned long i,
 nonrev_pk_t pk,
 nonrev_sk_t sk,
 accumulator_t acc,
 accumulator_pk_t acc_pk,
 accumulator_sk_t acc_sk,
 nonrev_pre_credential_prepare_t nrpc_prep)
{
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
  mpz_t mpz_i;
  mpz_init(mpz_i);
  mpz_set_ui(mpz_i, i);

  element_t temp;
  element_init_same_as(temp, nrpc->c); // in Zr
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
