#include "idemix_primary_credential.h"
#include "idemix_random.h"

void primary_credential_init
(primary_credential_t pc,
 schema_t s) // l = |Cs| in the schema
{
  mpz_inits(pc->e, pc->A, pc->v, NULL);
  attr_vec_init(pc->Cs, s->l);
}

void primary_credential_clear(primary_credential_t pc)
{
  mpz_clears(pc->e, pc->A, pc->v, NULL);
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

int primary_pre_credential_verify
(primary_pre_credential_t ppc,
 issuer_pk_t pk,
 issuer_sk_t sk,
 mpz_t n1,
 primary_credential_t pc)
{
  int retval = 0;
  mpz_t Q, A_caret, t;
  mpz_inits(Q, A_caret, t, NULL);

  do {
    // 2. verify e is prime and satisfies Eq. (10)
    if (!mpz_probab_prime_p(ppc->e, REPS_VAL)) {
      gmp_printf("e is not prime: %Z", ppc->e);
      retval = -1;
      break;
    }

    mpz_set_ui(t, 0);
    mpz_setbit(t, 596);
    if (mpz_cmp(ppc->e, t) < 0) {
      gmp_printf("e < 2^596: %Zd\n", ppc->e);
      retval = -1;
      break;
    }

    mpz_setbit(t, 119);
    if (mpz_cmp(t, ppc->e) < 0) {
      gmp_printf("e > 2^596 + 2^119: %Zd\n", ppc->e);
      retval = -1;
      break;
    }

    // 3. Compute Q, page 5 Eq. (20)
    mpz_powm(Q, pk->S, pc->v, pk->n);
    for (unsigned long i = 0; i < attr_vec_size(pc->Cs); ++i) {
      attr_ptr ap = attr_vec_head(pc->Cs) + i;
      if (i != ap->i) {
	gmp_printf("Cs(Ah + Ak) not okay, i = %d, ap->i: %d\n", i, ap->i);
	retval = -1;
	break;
      }
      mpz_powm(t, pk->R_v + i, ap->v, pk->n);
      mpz_mul(Q, Q, t);
      mpz_mod(Q, Q, pk->n);
    }
    if (retval) {
      break; // ...
    }
    mpz_invert(Q, Q, pk->n);
    mpz_mul(Q, pk->Z, Q);
    mpz_mod(Q, Q, pk->n);

    {
      gmp_printf("Q(20): %Zd\n", Q);
      gmp_printf("A: %Zd\n", pc->A);
      mpz_mul(t, sk->p_apos, sk->q_apos);
      mpz_invert(t, pc->e, t);
      mpz_powm(t, Q, t, pk->n);
      gmp_printf("A: %Zd\n", t);
      mpz_powm(t, t, pc->e, pk->n);
      gmp_printf("Q: %Zd\n", t);
    }

    // 4. Verify Q = A^e page 4
    // dx: TODO: how to do this???

    mpz_powm(t, pc->A, pc->e, pk->n);
    if (mpz_cmp(Q, t)) {
      gmp_printf("Q != A^e\nA^e: %Zd\nQ : %Zd\n A : %Zd\ne: %Zd\n",
		 t, Q, pc->A, ppc->e);
      // retval = -1;
      break;
    }

    // 5. Compute A^ = A^(c' + s_e*e) Eq. (21)
    mpz_mul(t, ppc->s_e, pc->e);
    mpz_add(t, ppc->c_apos, t);
    mpz_powm(A_caret, pc->A, t, pk->n); // t = A^

    // 6. Verify c′=H(Q||A||A^||n2)
    sm3_mpzs(t, Q, pc->A, A_caret, n1, NULL);

    // gmp_printf("verify:\nQ : %Zd\nA : %Zd\nA^: %Zd\nn1: %Zd\n",
    //	       Q, ppc->A, A_caret, n1);

    // dx: TODO: how to check this?
    /*
    if (mpz_cmp(t, ppc->c_apos)) {
      gmp_printf("c' != H(Q||A||A^||n1)\nc': %Zd\nH : %Zd\n",
		 ppc->c_apos, t);
      retval = -1;
      break;
    }
    */
  } while(0);

  mpz_clears(Q, A_caret, t, NULL);
  return retval;
}
