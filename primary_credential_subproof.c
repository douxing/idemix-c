#include "idemix_primary_credential_subproof.h"
#include "idemix_random.h"
#include "idemix_mpz_vec.h"

void primary_credential_subproof_init
(primary_credential_subproof_t p,
 const unsigned long l)
{
  mpz_inits(p->e_caret,
	    p->v_caret,
	    p->A_apos);
  attr_vec_init(p->m_carets, l);
}

void primary_credential_subproof_clear(primary_credential_subproof_t p)
{
  mpz_clears(p->e_caret,
	     p->v_caret,
	     p->A_apos);
  attr_vec_clear(p->m_carets);
}

void primary_credential_subproof_assign
(primary_credential_subproof_t pcsp,
 mpz_t CH,            // result of Eq. (41)
 attr_vec_t m_tildes, // Intersection(Cs, Ar_bar)
 primary_credential_t pc,
 primary_credential_subproof_auxiliary_t pcspa,
 mpz_t A_apos) // from tuple C
{
  // Eq. (42)
  mpz_mul(pcsp->e_caret, CH, pcspa->e_apos);
  mpz_add(pcsp->e_caret, pcspa->e_tilde, pcsp->e_caret);

  // Eq. (43)
  mpz_mul(pcsp->v_caret, CH, pcspa->v_apos);
  mpz_add(pcsp->v_caret, pcspa->v_tilde, pcsp->v_caret);

  for (unsigned long i = 0; i < attr_vec_size(m_tildes); ++i) { // Eq. (44)
    attr_ptr m_tilde = attr_vec_head(m_tildes) + i;
    attr_ptr m       = attr_vec_head(pc->Cs) + m_tilde->i;
    attr_ptr m_caret = attr_vec_head(pcsp->m_carets) + i;
    m_caret->i = m_tilde->i;
    mpz_mul(m_caret->v, CH, m->v);
    mpz_add(m_caret->v, m_tilde->v, m_caret->v);
  }

  mpz_set(pcsp->A_apos, A_apos);
}
