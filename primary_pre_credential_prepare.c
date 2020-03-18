#include "idemix_primary_pre_credential_prepare.h"
#include "idemix_random.h"

void primary_pre_credential_prepare_init
(primary_pre_credential_prepare_t ppc_prep,
 schema_t s)
{
  mpz_inits(ppc_prep->U,
	    ppc_prep->c,
	    ppc_prep->v_apos_caret,
	    ppc_prep->n1,
	    NULL);
  attr_vec_init(ppc_prep->m_carets, schema_attr_cnt_hidden(s));
}

void primary_pre_credential_prepare_clear
(primary_pre_credential_prepare_t ppc_prep)
{
  mpz_clears(ppc_prep->U,
	     ppc_prep->c,
	     ppc_prep->v_apos_caret,
	     ppc_prep->n1,
	     NULL);
  attr_vec_clear(ppc_prep->m_carets);

}

void primary_pre_credential_prepare_assign
(primary_pre_credential_prepare_t ppc_prep,
 issuer_pk_t pk,
 mpz_t n0,
 mpz_t v_apos,
 attr_vec_t Ah) // passed in by holder, so this is known here
{
  unsigned long l = attr_vec_size(Ah);
  mpz_t t, U_tilde, v_apos_tilde;
  mpz_inits(t, U_tilde, v_apos_tilde, NULL);
  attr_vec_t Ahr;

  // 5.1 Generate random 593-bit {mi~} i in Ah, and random 673-bit v'~
  attr_vec_init_random(Ahr, l, 593);
  random_num_exact_bits(v_apos_tilde, 673);
  
  // Eq. (5) (6)
  mpz_powm(ppc_prep->U, pk->S, v_apos, pk->n);
  mpz_powm(U_tilde, pk->S, v_apos_tilde, pk->n);
  for (unsigned long i = 0; i < l; ++i) {
    attr_ptr ap = attr_vec_head(Ah) + i;

    // Ri^mi
    mpz_powm(t, pk->R_v[ap->i], ap->v, pk->n);
    mpz_mul(ppc_prep->U, ppc_prep->U, t);
    mpz_mod(ppc_prep->U, ppc_prep->U, pk->n);

    // Ri^mi~
    attr_ptr apr = attr_vec_head(Ahr) + i;
    mpz_powm(t, pk->R_v[ap->i], apr->v, pk->n);
    mpz_mul(U_tilde, U_tilde, t);
    mpz_mod(U_tilde, U_tilde, pk->n);
  }

  // Eq. (7)
  sm3_mpzs(ppc_prep->c, ppc_prep->U, U_tilde, n0);
  mpz_mul(t, ppc_prep->c, v_apos);
  mpz_add(ppc_prep->v_apos_caret, v_apos_tilde, t);

  // Eq. (8)
  for (unsigned long i = 0; i < l; ++i) {
    attr_ptr m = attr_vec_head(Ah) + i;
    attr_ptr m_tilde = attr_vec_head(Ahr) + i;
    attr_ptr m_caret = attr_vec_head(ppc_prep->m_carets) + i;
    mpz_mul(t, ppc_prep->c, m->v);
    mpz_add(m_caret->v, m_tilde->v, t);
    m_caret->i = m->i;
  }

  // 7.2 Generate random 80-bit nonce n1
  random_num_exact_bits(ppc_prep->n1, 80);
  
  mpz_clears(t, U_tilde, NULL);
}

// 0 == ok else = error
int primary_pre_credential_prepare_verify
(primary_pre_credential_prepare_t ppc_prep,
 issuer_pk_t pk,
 mpz_t n0)
{
  int ret = 0;
  mpz_t t, t1, U_caret;
  mpz_inits(t, t1, U_caret, NULL);

  do {
    // Eq. (9)
    mpz_invert(U_caret, ppc_prep->U, pk->n);
    mpz_powm(U_caret, U_caret, ppc_prep->c, pk->n);
    for (unsigned long i = 0; i < attr_vec_size(ppc_prep->m_carets); ++i) {
      attr_ptr ap = attr_vec_head(ppc_prep->m_carets) + i;
      mpz_powm(t, pk->R_v[ap->i], ap->v, pk->n);
      mpz_mul(U_caret, U_caret, t);
      mpz_mod(U_caret, U_caret, pk->n);
    }
    mpz_powm(t, pk->S, ppc_prep->v_apos_caret, pk->n);
    mpz_mul(U_caret, U_caret, t);
    mpz_mod(U_caret, U_caret, pk->n);

    sm3_mpzs(t, ppc_prep->U, U_caret, n0);
    if (t != ppc_prep->c) {
      gmp_printf("c^ and c don't the same!");
      ret = -1;
      break;
    }

    // 3. Verify that̂v′is a 673-bit number,{̂mi,̂ri}i∈Acare 594-bit numbers
    // TODO
  }
  while (0);
  mpz_clears(t, t1, U_caret, NULL);
  return ret;
}
