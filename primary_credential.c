#include "idemix_primary_credential.h"
#include "idemix_random.h"

void primary_credential_init
(primary_credential_t pc,
 schema_t s) // l = |Cs| in the schema
{
  mpz_inits(pc->e, pc->A, pc->v);
  attr_vec_init(pc->Cs, s->l);
}

void primary_credential_clear(primary_credential_t pc)
{
  mpz_inits(pc->e, pc->A, pc->v);
  attr_vec_clear(pc->Cs);
}

void primary_credential_assign
(primary_credential_t pc,
 mpz_t v_apos,
 attr_vec_t Ah,
 primary_pre_credential_t ppc)
{
  attr_vec_combine(pc->Cs, Ah, ppc->Ak);
  mpz_set(pc->A, ppc->A);
  mpz_set(pc->e, ppc->e);
  mpz_add(pc->v, v_apos, ppc->v_apos_apos);
}

int primary_credential_verify
(primary_credential_t pc,
 issuer_pk_t pk,
 mpz_t n1,
 primary_pre_credential_t ppc)
{
  int ret = 0;
  mpz_t Q, A_caret, t;
  mpz_inits(Q, A_caret, t);

  do {
    // assert pc->e == ppc->e, pc->A == ppc->A

    // Eq. (20)
    mpz_powm(Q, pk->S, pc->v, pk->n);
    for (unsigned long i = 0; i < attr_vec_size(pc->Cs); ++i) {
      attr_ptr ap = attr_vec_head(pc->Cs) + i;
      if (i != ap->i) {
	ret = -1;
	break;
      }
      mpz_powm(t, pk->R_v[i], ap->v, pk->n);
      mpz_mul(Q, Q, t);
      mpz_mod(Q, Q, pk->n);
    }
    mpz_invert(Q, Q, pk->n);
    mpz_mul(Q, pk->Z, Q);
    mpz_mod(Q, Q, pk->n);

    // 4. Verify Q = A^e page 4
    mpz_powm(t, pc->A, pc->e, pk->n);
    if (mpz_cmp(Q, t)) {
      ret = -1;
      break;
    }

    // 5. Compute A^ = A^(c' + s_e*e) Eq. (21)
    mpz_mul(t, ppc->s_e, pc->e);
    mpz_add(t, ppc->c_apos, t);
    mpz_powm(A_caret, pc->A, t, pk->n); // t = A^

    // 6. Verifyc′=H(Q||A||̂A||n2)
    sm3_mpzs(t, Q, pc->A, A_caret, n1);
    if (mpz_cmp(t, ppc->c_apos)) {
      ret = -1;
      break;      
    }
  } while(0);

  mpz_clears(Q, A_caret, t);
  return ret;
}
