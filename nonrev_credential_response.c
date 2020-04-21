#include "idemix_nonrev_credential_response.h"

void nonrev_credential_response_init
(nonrev_credential_response_t nrc_res, // OUT
 pairing_t pairing)
{
  // initialized pairing members
  element_init_GT(nrc_res->IA, pairing);
  element_init_G1(nrc_res->sigma, pairing);
  element_init_Zr(nrc_res->c, pairing);
  element_init_Zr(nrc_res->s_apos_apos, pairing);

  witness_init(nrc_res->wit_i, pairing);

  element_init_G1(nrc_res->g_i, pairing);
  element_init_G2(nrc_res->g_apos_i, pairing);
}

void nonrev_credential_response_clear
(nonrev_credential_response_t nrc_res)
{
  // initialized pairing members
  element_clear(nrc_res->IA);
  element_clear(nrc_res->sigma);
  element_clear(nrc_res->c);
  element_clear(nrc_res->s_apos_apos);

  witness_clear(nrc_res->wit_i);

  element_clear(nrc_res->g_i);
  element_clear(nrc_res->g_apos_i);
}

void nonrev_credential_response_assign
(nonrev_credential_response_t nrc_res,
 mpz_t m2,
 unsigned long i,
 nonrev_pk_t pk,
 nonrev_sk_t sk,
 accumulator_t acc,
 accumulator_pk_t acc_pk,
 accumulator_sk_t acc_sk,
 nonrev_credential_request_t nrc_req)
{
  // 1. Generate random numbers s", c mod q.
  element_random(nrc_res->s_apos_apos);
  element_random(nrc_res->c);

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
  mpz_set_ui(mpz_i, i + 1);

  element_t temp;
  element_init_same_as(temp, nrc_res->c); // in Zr
  element_set_mpz(temp, m2);
  element_pow2_zn(nrc_res->sigma, pk->h1, temp, pk->h2, nrc_res->s_apos_apos);
  element_mul(nrc_res->sigma, nrc_res->sigma, pk->h0);
  element_mul(nrc_res->sigma, nrc_res->sigma, nrc_req->U);
  element_mul(nrc_res->sigma, nrc_res->sigma, acc->g1_v[i]);

  element_add(temp, sk->x, nrc_res->c);
  element_invert(temp, temp);
  element_pow_zn(nrc_res->sigma, nrc_res->sigma, temp);

  compute_w(nrc_res->wit_i->w, acc, i);
  
  // page 5 Eq. (17)
  element_pow_mpz(temp, acc_sk->gamma, mpz_i); // temp = gamma^i
  element_pow_zn(nrc_res->wit_i->u_i, pk->u, temp); // u_i
  
  element_add(temp, sk->sk, temp); // temp = sk + gamma^i
  element_invert(temp, temp);      // temp = 1 / (sk + gamma^i)
  element_pow_zn(nrc_res->wit_i->sigma_i, acc->g_apos, temp); // sigma_i

  // page 5 Eq. (18)
  element_mul(acc->acc, acc->acc, acc->g2_v[acc->L - 1 - i]); // A
  bitmap_setbit(acc->V, i); // V

  // page 5 Eq. (19)
  // already set: sigma_i, u_i, w
  element_set(nrc_res->wit_i->g_i, acc->g1_v[i]);
  bitmap_set(nrc_res->wit_i->V, acc->V);

  // set the rest members in non-revocation pre-credential
  element_set(nrc_res->IA, acc_pk->z);
  element_set(nrc_res->g_i, acc->g1_v[i]);
  element_set(nrc_res->g_apos_i, acc->g2_v[i]);
  nrc_res->i = i;
  
  element_clear(temp);
  mpz_clear(mpz_i);
}
