#ifndef __IDEMIX_ISSUER_H__
#define __IDEMIX_ISSUER_H__

typedef struct issuer_pk_R_s *issuer_pk_R_ptr;
struct issuer_pk_R_s {
  mpz_t R;
  issuer_pk_R_ptr next;
};

struct issuer_pk_s {
  mpz_t n;  
  mpz_t S;
  mpz_t Z;
  unsigned long R_c;
  issuer_pk_R_ptr R_v;
};
typedef struct issuer_pk_s *issuer_pk_ptr;
typedef struct issuer_pk_s issuer_pk_t[1];

typedef struct issuer_sk_x_s *issuer_sk_x_ptr;
struct issuer_sk_x_s {
  mpz_t x;
  issuer_pk_R_ptr next;
};

struct issuer_sk_s {
  mpz_t p_apos;
  mpz_t q_apos;
  mpz_t p;
  mpz_t q;
  unsigned long x_c;
  issuer_sk_x_ptr x_v;
};
typedef struct issuer_sk_s *issuer_sk_ptr;
typedef struct issuer_sk_s issuer_sk_t[1];

struct revok_pk_s {};
typedef struct revok_pk_s *revok_pk_ptr;
typedef struct revok_pk_s revok_pk_t[1];

struct revok_sk_s {
  
};
typedef struct revok_sk_s *revok_sk_ptr;
typedef struct revok_sk_s revok_sk_t[1];

struct accum_pk_s {};
typedef struct accum_pk_s *accum_pk_ptr;
typedef struct accum_pk_s accum_pk_t[1];

struct accum_sk_s {};
typedef struct accum_sk_s *accum_sk_ptr;
typedef struct accum_sk_s accum_sk_t[1];


// section 4.2 Primary Credential Cryptographic setup
// attr_c: supported attribute number
// pk, sk: un-setup keys
void issuer_keys_setup(unsigned long attr_c, issuer_pk_t pk, issuer_sk_t sk);

// TODO: section 4.3

// section 4.4 Non-revokation Credential Cryptographic setup
void revok_keys_setup(revok_pk_t pk, revok_sk_t sk);

// section 4.4.1
void accum_setup(accum_pk_t pk, accum_sk_t sk);

void init_CS(int attrc, char *attrv[], issuer_pk_t);


#endif
