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
 primary_credential_response_t pc_res)
{
  attr_vec_combine(pc->Cs, Ah, pc_res->Ak);
  mpz_set(pc->A, pc_res->A);
  mpz_set(pc->e, pc_res->e);
  mpz_add(pc->v, v_apos, pc_res->v_apos_apos);
}

int primary_credential_response_verify
(primary_credential_response_t pc_res,
 issuer_pk_t pk,
 mpz_t n1,
 primary_credential_t pc)
{
  int retval = 0;
  mpz_t Q, A_caret, t;
  mpz_inits(Q, A_caret, t, NULL);

  do {
    // 2. verify e is prime and satisfies Eq. (10)
    if (!mpz_probab_prime_p(pc_res->e, REPS_VAL)) {
      gmp_printf("e is not prime: %Z", pc_res->e);
      retval = -1;
      break;
    }

    mpz_set_ui(t, 0);
    mpz_setbit(t, 596);
    if (mpz_cmp(pc_res->e, t) < 0) {
      gmp_printf("e < 2^596: %Zd\n", pc_res->e);
      retval = -1;
      break;
    }

    mpz_setbit(t, 119);
    if (mpz_cmp(t, pc_res->e) < 0) {
      gmp_printf("e > 2^596 + 2^119: %Zd\n", pc_res->e);
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

    // 4. Verify Q = A^e page 4
    mpz_powm(t, pc->A, pc->e, pk->n);
    if (mpz_cmp(Q, t)) {
      gmp_printf("Q != A^e\nA^e: %Zd\nQ : %Zd\n A : %Zd\ne: %Zd\n",
                 t, Q, pc->A, pc_res->e);
      retval = -1;
      break;
    }

    // 5. Compute A^ = A^(c' + s_e*e) Eq. (21)
    mpz_mul(t, pc_res->s_e, pc->e);
    mpz_add(t, pc_res->c_apos, t);
    mpz_powm(A_caret, pc->A, t, pk->n); // t = A^

    // 6. Verify c′=H(Q||A||A^||n2)
    sm3_mpzs(t, Q, pc->A, A_caret, n1, NULL);

    // gmp_printf("verify:\nQ : %Zd\nA : %Zd\nA^: %Zd\nn1: %Zd\n",
    //	       Q, pc_res->A, A_caret, n1);

    if (mpz_cmp(t, pc_res->c_apos)) {
      gmp_printf("c' != H(Q||A||A^||n1)\nc': %Zd\nH : %Zd\n",
                 pc_res->c_apos, t);
      retval = -1;
      break;
    }
  } while(0);

  mpz_clears(Q, A_caret, t, NULL);
  return retval;
}
