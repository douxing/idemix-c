#include "idemix_random.h"
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
				  mpz_t n1, //
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

    // 6. verify c' = H(Q||A||A^||n1)
    sm3_mpzs(temp, Q, ppc->A, A_caret, n1);
    if (mpz_cmp(ppc->c_apos, temp)) {
      gmp_printf("c' != H(Q||A||A^||n1)\nc': %Z\nH : %Z",
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

// Chapter 7

void non_revok_proof
(nr_proof_t nrp, // OUT
 nr_cred_t nrc,  // OUT
 nr_pk_t pk,
 accumulator_t acc,
 proof_randomness_t r)
{
  // 1. Load Issuer's public revocation key
  // 2. Load the non-revocation credential C_NR
  // 3. Obtain recent V, acc

  // 4. Update C_NR
  non_revok_credential_update(nrc, acc);

  // 5. Select random ... mod q

  // 6. Compute
  //    E, D, A, G, W, S, U in Eq. (22) ~ (25)
  element_pow2_zn(nrp->E, pk->h, r->rho, pk->h_tilde, r->o); // E
  element_pow2_zn(nrp->D, acc->g, r->r, pk->h_tilde, r->o_apos); // D
  element_pow_zn(nrp->A, pk->h_tilde, r->rho);
  element_mul(nrp->A, nrc->sigma, nrp->A); // A
  element_pow_zn(nrp->G, pk->h_tilde, r->r);
  element_mul(nrp->G, nrc->g_i, nrp->G); // G
  element_pow_zn(nrp->W, pk->h_caret, r->r_apos);
  element_mul(nrp->W, nrc->wit_i->w, nrp->W); // W
  element_pow_zn(nrp->S, pk->h_caret, r->r_apos2);
  element_mul(nrp->S, nrc->wit_i->sigma_i, nrp->S); // S
  element_pow_zn(nrp->U, pk->h_caret, r->r_apos3);
  element_mul(nrp->U, nrc->wit_i->u_i, nrp->U); // U
  
  // page 7 Eq. (26) (27)
  element_mul(nrp->m, r->rho, nrc->c);
  element_mul(nrp->t, r->o, nrc->c);
  element_mul(nrp->m_apos, r->r, r->r_apos2);
  element_mul(nrp->t_apos, r->o_apos, r->r_apos2);

  // page 7 Eq. (28) ~ (32)
  element_t t, t1, t2, t3;

  // T1 bar
  element_pow2_zn(nrp->T1_bar,
		  pk->h, r->rho_tilde,
		  pk->h_tilde, r->o_tilde);

  // T2 bar
  element_init_same_as(t1, nrp->T2_bar);
  element_init_same_as(t2, nrp->T2_bar);
  element_invert(t1, pk->h);
  element_invert(t2, pk->h_tilde);
  element_pow3_zn(nrp->T2_bar,
		  nrp->E, r->c_tilde,
		  t1, r->m_tilde,
		  t2, r->t_tilde);
  element_clear(t1);
  element_clear(t2);

  // T3 bar
  element_init_same_as(t, nrp->T3_bar);
  element_init_same_as(t1, nrp->T3_bar);
  element_init_same_as(t2, nrp->T3_bar);
  element_init_same_as(t3, nrp->T3_bar);
  element_pairing(t1, nrp->A, pk->h_caret);
  element_pairing(t2, pk->h_tilde, pk->h_caret);
  element_pairing(t3, pk->h_tilde, pk->y);
  element_invert(t3, t3);
  element_pow3_zn(nrp->T3_bar,
		  t1, r->c_tilde,
		  t2, r->r_tilde,
		  t3, r->rho_tilde);
  element_pairing(t1, pk->h_tilde, pk->h_caret);
  element_invert(t1, t1);
  element_pairing(t2, pk->h1, pk->h_caret);
  element_invert(t2, t2);
  element_pairing(t3, pk->h2, pk->h_caret);
  element_invert(t3, t3);
  element_pow3_zn(t, t1, r->m_tilde, t2, r->m2_tilde, t3, r->s_tilde);
  element_mul(nrp->T3_bar, nrp->T3_bar, t);
  element_clear(t);
  element_clear(t1);
  element_clear(t2);
  element_clear(t3);

  // T4 bar
  element_init_same_as(t, acc->g);
  element_init_same_as(t1, nrp->T4_bar);
  element_init_same_as(t2, nrp->T4_bar);
  element_pairing(t1, pk->h_tilde, acc->acc);
  element_invert(t, t);
  element_pairing(t2, t, pk->h_caret);
  element_pow2_zn(nrp->T4_bar,
		  t1, r->r_tilde,
		  t2, r->r_apos_tilde);
  element_clear(t);
  element_clear(t1);
  element_clear(t2);  

  // T5 bar
  element_pow2_zn(nrp->T5_bar,
		  acc->g, r->r_tilde,
		  pk->h_tilde, r->o_apos_tilde);

  // T6 bar
  element_init_same_as(t1, nrp->T6_bar);
  element_init_same_as(t2, nrp->T6_bar);
  element_invert(t1, acc->g);
  element_invert(t2, pk->h_tilde);
  element_pow3_zn(nrp->T6_bar,
		  nrp->D, r->r_apos2,
		  t1, r->m_apos_tilde,
		  t2, r->t_apos_tilde);
  element_clear(t1);
  element_clear(t2);

  // T7 bar
  element_init_same_as(t, pk->pk);
  element_init_same_as(t1, nrp->T7_bar);
  element_init_same_as(t2, nrp->T7_bar);
  element_init_same_as(t3, nrp->T7_bar);
  element_mul(t, pk->pk, nrp->G);
  element_pairing(t1, t, pk->h_caret);
  element_pairing(t2, pk->h_tilde, pk->h_caret);
  element_invert(t2, t2);
  element_pairing(t3, pk->h_tilde, nrp->S);
  element_pow3_zn(nrp->T7_bar,
		  t1, r->r_apos2_tilde,
		  t2, r->m_apos_tilde,
		  t3, r->r_tilde);
  element_clear(t);
  element_clear(t1);
  element_clear(t2);
  element_clear(t3);

  // T8 bar
  element_init_same_as(t, acc->g);
  element_init_same_as(t1, nrp->T8_bar);
  element_init_same_as(t2, nrp->T8_bar);
  element_pairing(t1, pk->h_tilde, pk->u);
  element_invert(t, acc->g);
  element_pairing(t2, t, pk->h_caret);
  element_pow2_zn(nrp->T8_bar,
		  t1, r->r_tilde,
		  t2, r->r_apos3_tilde);
}

// end of Chapter 7
