#include "idemix_primary_subproof.h"

void primary_subproof_prepare_init(primary_subproof_prepare_t p)
{
  mpz_inits(p->r,
	    p->A_apos,
	    p->v_apos,
	    p->e_apos,
	    p->v_tilde,
	    p->e_tilde,
	    p->T);
}

void primary_subproof_prepare_clear(primary_subproof_prepare_t p)
{
  mpz_clears(p->r,
	     p->A_apos,
	     p->v_apos,
	     p->e_apos,
	     p->v_tilde,
	     p->e_tilde,
	     p->T);
}

void primary_subproof_prepare_assign
(primary_subproof_prepare_t psp_prep,
 attr_vec_t m_tildes, // = Intersection(Cs, Ar_bar)
 primary_credential_t pc,
 issuer_pk_t pk)
{
  random_num_exact_bits(psp_prep->r, 2128); // 2.1

  // 2.2 Eq. (33)
  mpz_powm(psp_prep->A_apos, pk->S, psp_prep->r, pk->n);
  mpz_mul(psp_prep->A_apos, pc->A, psp_prep->A_apos);
  mpz_mod(psp_prep->A_apos, psp_prep->A_apos, pk->n); // A' = AS_r

  mpz_mul(psp_prep->v_apos, pc->e, psp_prep->r);
  mpz_sub(psp_prep->v_apos, pc->v, psp_prep->v_apos); // v' = v - er

  // 2.3 e' = e - 2^596
  mpz_set_ui(psp_prep->e_apos, 0);
  mpz_setbit(psp_prep->e_apos, 596);
  mpz_sub(psp_prep->e_apos, pc->e, psp_prep->e_apos);

  random_num_exact_bits(psp_prep->e_tilde, 456);  // 2.4
  random_num_exact_bits(psp_prep->v_tilde, 3060); // 2.5

  // 2.6 Eq. (34)
  mpz_t t;
  mpz_init(t);
  mpz_powm(psp_prep->T, psp_prep->A_apos, psp_prep->e_tilde, pk->n); // 1st item
  for (unsigned long i = 0; i < attr_vec_size(m_tildes); ++i) {
    attr_ptr ap = attr_vec_head(m_tildes) + i;
    mpz_powm(t, pk->R_v[ap->i], ap->v, pk->n);
    mpz_mul(psp_prep->T, psp_prep->T, t);
    mpz_mod(psp_prep->T, psp_prep->T, pk->n);
  }
  mpz_powm(t, pk->S, psp_prep->v_tilde, pk->n);
  mpz_mul(psp_prep->T, psp_prep->T, t);
  mpz_mod(psp_prep->T, psp_prep->T, pk->n);  

  mpz_clear(t);
}

void primary_subproof_prepare_into_C(mpz_vec_t C, // OUT
				  primary_subproof_prepare_t psp_prep)
{
  mpz_vec_append(C, psp_prep->A_apos);
}

void primary_subproof_prepare_into_T(mpz_vec_t T, // OUT
				  primary_subproof_prepare_t psp_prep)
{
  mpz_vec_append(T, psp_prep->T);
}

void primary_subproof_init(primary_subproof_t p,
			   const unsigned long l)
{
  mpz_inits(p->e_caret,
	    p->v_caret,
	    p->A_apos);
  attr_vec_init(p->m_carets, l);
}

void primary_subproof_clear(primary_subproof_t p)
{
  mpz_clears(p->e_caret,
	     p->v_caret,
	     p->A_apos);
  attr_vec_clear(p->m_carets);
}

void primary_subproof_assign(primary_subproof_t psp,
			     mpz_t CH, // result of Eq. (41)
			     attr_vec_t m_tildes, // Intersection(Cs, Ar_bar)
			     primary_credential_t pc,
			     primary_subproof_prepare_t r)
{
  
  // Eq. (42)
  mpz_mul(psp->e_caret, CH, r->e_apos);
  mpz_add(psp->e_caret, r->e_tilde, psp->e_caret);

  // Eq. (43)
  mpz_mul(psp->v_caret, CH, r->v_apos);
  mpz_add(psp->v_caret, r->v_tilde, psp->v_caret);

  for (unsigned long i = 0; i < attr_vec_size(m_tildes); ++i) { // Eq. (44)
    attr_ptr m_tilde = attr_vec_head(m_tildes) + i;
    attr_ptr m       = attr_vec_head(pc->Cs) + m_tilde->i;
    attr_ptr m_caret = attr_vec_head(psp->m_carets) + i;
    m_caret->i = m_tilde->i;
    mpz_mul(m_caret->v, CH, m->v);
    mpz_add(m_caret->v, m_tilde->v, m_caret->v);
  }

  mpz_set(psp->A_apos, r->A_apos);
}
