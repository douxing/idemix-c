#include "idemix_nonrev_key.h"
#include "idemix_random.h"
#include "idemix_bitmap.h"

// section 4.4 Non-revokation Credential Cryptographic setup
// pk, sk : to be initialized element
// pairing: pairing parameter
// g      : the generator of G1
// g_apos : the generator of G2
void nonrev_keys_init_assign(nonrev_sk_t sk, // OUTPUT
			     nonrev_pk_t pk, // OUTPUT
			     pairing_t pairing,
			     element_t g,
			     element_t _g_apos)
{
  (void)_g_apos;

  // init secret key
  element_init_Zr(sk->x, pairing);
  element_init_Zr(sk->sk, pairing);
  element_random(sk->x);
  element_random(sk->sk);

  // init public key
  element_init_G1(pk->h, pairing);
  element_init_G1(pk->h0, pairing);
  element_init_G1(pk->h1, pairing);
  element_init_G1(pk->h2, pairing);
  element_init_G1(pk->h_tilde, pairing);
  element_random(pk->h);
  element_random(pk->h0);
  element_random(pk->h1);
  element_random(pk->h2);
  element_random(pk->h_tilde);

  element_init_G2(pk->u, pairing);
  element_init_G2(pk->h_caret, pairing);
  element_random(pk->u);
  element_random(pk->h_caret);

  element_init_G1(pk->pk, pairing);
  element_init_G2(pk->y, pairing);
  element_pow_zn(pk->pk, g, sk->sk);
  element_pow_zn(pk->y, pk->h_caret, sk->x);
}

void nonrev_sk_clear(nonrev_sk_t sk)
{
  element_clear(sk->sk);
  element_clear(sk->x);
}


void nonrev_pk_clear(nonrev_pk_t pk)
{
  element_clear(pk->h);
  element_clear(pk->h0);
  element_clear(pk->h1);
  element_clear(pk->h2);
  element_clear(pk->h_tilde);

  element_clear(pk->u);
  element_clear(pk->h_caret);

  element_clear(pk->pk);
  element_clear(pk->y);  
}

// 4.4.1 New Accumulator Setup:

// end of 4.4.1
// end of 4.4
// end of Chapter 4

// Chapter 7:

// end of Chapter 7
