#ifndef __IDEMIX_ISSUER_H__
#define __IDEMIX_ISSUER_H__

#include <pbc/pbc.h>

// Chapter 4:
struct issuer_pk_s {
  mpz_t n;  
  mpz_t S;
  mpz_t Z;
  unsigned long R_c;
  mpz_t *R_v;
};
typedef struct issuer_pk_s *issuer_pk_ptr;
typedef struct issuer_pk_s issuer_pk_t[1];

struct issuer_sk_s {
  mpz_t p_apos;
  mpz_t q_apos;
  mpz_t p;
  mpz_t q;
  mpz_t xZ;
  unsigned long xR_c;
  mpz_t *xR_v;
};
typedef struct issuer_sk_s *issuer_sk_ptr;
typedef struct issuer_sk_s issuer_sk_t[1];

struct nonrev_pk_s {
  // in G1
  element_t h;
  element_t h0;
  element_t h1;
  element_t h2;
  element_t h_tilde;

  // in G2
  element_t u;
  element_t h_caret;

  // in Zr
  element_t pk;
  element_t y;
};
typedef struct nonrev_pk_s *nonrev_pk_ptr;
typedef struct nonrev_pk_s nonrev_pk_t[1];

struct nonrev_sk_s {
  element_t sk;
  element_t x;
};
typedef struct nonrev_sk_s *nonrev_sk_ptr;
typedef struct nonrev_sk_s nonrev_sk_t[1];

// section 4.2 Primary Credential Cryptographic setup
// attr_c: supported attribute number
// pk, sk: un-setup keys
void issuer_keys_setup(unsigned long L, issuer_pk_t pk, issuer_sk_t sk);

// TODO: section 4.3

// section 4.4 Non-revokation Credential Cryptographic setup
void nonrev_keys_setup(pairing_t pairing,
		       element_t g, element_t g_apos,
		       nonrev_pk_t pk, nonrev_sk_t sk);

// section 4.4.1 New Accumulator Setup
// @see include/idemix_accumulator.h

// end of Chapter 4

// chapter 5:

struct primary_pre_credential_s {
  // {mi} is in the schema
  mpz_t A;
  mpz_t v_apos_apos;
  mpz_t e;
  mpz_t s_e;
  mpz_t c_apos;
};
typedef struct primary_pre_credential_s *prim_pre_cred_ptr;
typedef struct primary_pre_credential_s prim_pre_cred_t[1];

// 5.2 Primary Credential Issurance
struct primary_pre_credential_prepare_s;
int issue_primary_pre_credential(issuer_pk_t pk,
				 issuer_sk_t sk,
				 struct primary_pre_credential_prepare_s *,
				 // prim_pre_cred_prep_t ppc_prep,
				 prim_pre_cred_t ppc,
				 schema_t schema,
				 mpz_t n0,
				 accumulator_t acc);

struct non_revokation_pre_credential_s {
  element_t IA; // IA = z = IDa in GT
  element_t sigma; // in G1
  element_t c; // in Zr
  element_t s_apos_apos; // in Zr

  // in witness element
  element_t sigma_i; // in G1
  element_t u_i;    // in G2
  // element_t g_i; duplicated definition
  element_t omega; // in G2
  index_vec_t V;

  element_t g_i; // in G1
  element_t g_apos_i; // in G2
  unsigned long i;
};
typedef struct non_revokation_pre_credential_s *nonrev_pre_cred_ptr;
typedef struct non_revokation_pre_credential_s nonrev_pre_cred_t[1];

// 5.3 Non-revocation Credential Issuance
struct non_revokation_pre_credential_prepare_s;
int issue_non_revokation_pre_credential(nonrev_pre_cred_t nrpc, // issuer -> holder
					pairing_t pairing,
					nonrev_pk_t pk,
					nonrev_sk_t sk,
					// holder -> issuer
					struct non_revokation_pre_credential_prepare_s aaa[],
					schema_t schema,
					accumulator_t acc,
					unsigned long i,
					accum_pk_t accum_pk,
					accum_sk_t accum_sk);

// end of Chapter 5

void init_CS(int attrc, char *attrv[], issuer_pk_t);


#endif
