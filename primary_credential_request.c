#include "idemix_primary_credential_request.h"
#include "idemix_random.h"

void primary_credential_request_init
(primary_credential_request_t pc_req,
 schema_t s)
{
  mpz_inits(pc_req->U,
            pc_req->c,
            pc_req->v_apos_caret,
            pc_req->n1,
            NULL);
  attr_vec_init(pc_req->m_carets, schema_attr_cnt_hidden(s));
}

void primary_credential_request_clear
(primary_credential_request_t pc_req)
{
  mpz_clears(pc_req->U,
             pc_req->c,
             pc_req->v_apos_caret,
             pc_req->n1,
             NULL);
  attr_vec_clear(pc_req->m_carets);

}

void primary_credential_request_assign
(primary_credential_request_t pc_req,
 issuer_pk_t pk,
 mpz_t n0,
 mpz_t v_apos,
 attr_vec_t Ah) // passed in by holder, so this is known here
{
  unsigned long l = attr_vec_size(Ah);

  mpz_t t, U_tilde, v_apos_tilde;
  mpz_inits(t, U_tilde, v_apos_tilde, NULL);

  // 5.1 Generate random 593-bit {mi~} i in Ah, and random 673-bit v'~
  attr_vec_t Ahr;
  attr_vec_init_random(Ahr, l, 593);
  random_num_exact_bits(v_apos_tilde, 673);
  
  // Eq. (5) (6)
  mpz_powm(pc_req->U, pk->S, v_apos, pk->n);
  mpz_powm(U_tilde, pk->S, v_apos_tilde, pk->n);
  for (unsigned long i = 0; i < l; ++i) {
    attr_ptr ap = attr_vec_head(Ah) + i; // Ri^mi
    mpz_powm(t, pk->R_v + ap->i, ap->v, pk->n);
    mpz_mul(pc_req->U, pc_req->U, t);
    mpz_mod(pc_req->U, pc_req->U, pk->n);

    attr_ptr apr = attr_vec_head(Ahr) + i; // Ri^mi~
    mpz_powm(t, pk->R_v + ap->i, apr->v, pk->n);
    mpz_mul(U_tilde, U_tilde, t);
    mpz_mod(U_tilde, U_tilde, pk->n);
  }

  // gmp_printf("U: %Zd\nU_tilde: %Zd\nn0: %Zd\n", pc_req->U, U_tilde, n0);

  // Eq. (7)
  sm3_mpzs(pc_req->c, pc_req->U, U_tilde, n0, NULL);

  mpz_mul(t, pc_req->c, v_apos);
  mpz_add(pc_req->v_apos_caret, v_apos_tilde, t);

  // Eq. (8)
  for (unsigned long i = 0; i < l; ++i) {
    attr_ptr m = attr_vec_head(Ah) + i;
    attr_ptr m_tilde = attr_vec_head(Ahr) + i;
    attr_ptr m_caret = attr_vec_head(pc_req->m_carets) + i;
    mpz_mul(t, pc_req->c, m->v);
    mpz_add(m_caret->v, m_tilde->v, t);
    m_caret->i = m->i;
  }

  // 7.2 Generate random 80-bit nonce n1
  random_num_exact_bits(pc_req->n1, 80);

  attr_vec_clear(Ahr);
  mpz_clears(t, U_tilde, v_apos_tilde, NULL);
}

// 0 == ok else = error
int primary_credential_request_verify
(primary_credential_request_t pc_req,
 issuer_pk_t pk,
 mpz_t n0)
{
  int ret = 0;
  mpz_t t, t1, U_caret;
  mpz_inits(t, t1, U_caret, NULL);

  do {
    // Eq. (9)
    mpz_neg(t, pc_req->c);
    mpz_powm(U_caret, pc_req->U, t, pk->n);
    for (unsigned long i = 0; i < attr_vec_size(pc_req->m_carets); ++i) {
      attr_ptr ap = attr_vec_head(pc_req->m_carets) + i;
      mpz_powm(t, pk->R_v + ap->i, ap->v, pk->n);
      mpz_mul(U_caret, U_caret, t);
      mpz_mod(U_caret, U_caret, pk->n);
    }
    mpz_powm(t, pk->S, pc_req->v_apos_caret, pk->n);
    mpz_mul(U_caret, U_caret, t);
    mpz_mod(U_caret, U_caret, pk->n);

    sm3_mpzs(t, pc_req->U, U_caret, n0, NULL);
    if (mpz_cmp(t, pc_req->c)) {
      gmp_printf("c^ and c don't the same:\nc^: %Zd\nc : %Zd\n",
                 t, pc_req->c);
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
