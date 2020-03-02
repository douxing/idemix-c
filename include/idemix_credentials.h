#ifndef __IDEMIX_CREDENTIALS_H__
#define __IDEMIX_CREDENTIALS_H__

#include "idemix_utils.h"
#include "idemix_crypto.h"
#include "idemix_schema.h"

// Chapter 5:

// 5.1 Holder Setup:

struct primary_pre_credential_prepare_s {
  mpz_t U;
  mpz_t c;
  mpz_t v_apos_caret;
  mpz_t m1_caret; // only m1(link secret) is needed
  mpz_t n1;
};
typedef struct primary_pre_credential_prepare_s *pri_pre_cred_prep_ptr;
typedef struct primary_pre_credential_prepare_s pri_pre_cred_prep_t[1];

void primary_pre_credential_prepare_init
(pri_pre_cred_prep_t ppc_prep);

struct non_revok_pre_credential_prepare_s {
  element_t U; // in G1
};
typedef struct non_revok_pre_credential_prepare_s *nr_pre_cred_prep_ptr;
typedef struct non_revok_pre_credential_prepare_s nr_pre_cred_prep_t[1];

void non_revok_pre_credential_prepare_init(nr_pre_cred_prep_t nrpc_prep, // OUT
					   pairing_t pairing);

// end of Chapter 5.1

// 5.2 Primary Credential Issurance:

struct primary_pre_credential_s {
  // {mi} is in the schema
  mpz_t A;
  mpz_t e;
  mpz_t v_apos_apos;
  mpz_t s_e;
  mpz_t c_apos;
};
typedef struct primary_pre_credential_s *pri_pre_cred_ptr;
typedef struct primary_pre_credential_s pri_pre_cred_t[1];

void primary_pre_credential_init(pri_pre_cred_t ppc);

// end of 5.2

// 5.3 Non-revocation Credential Issuance:

struct non_revok_pre_credential_s {
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
typedef struct non_revok_pre_credential_s *nr_pre_cred_ptr;
typedef struct non_revok_pre_credential_s nr_pre_cred_t[1];

void non_revok_pre_credential_init(nr_pre_cred_t nrpc, // OUT
				   pairing_t pairing);

void compute_m2(mpz_t m2,
		const mpz_t i,
		const mpz_t H_cop);

// end of 5.3

// 5.4 Storing Credentials

struct primary_credential_s {
};
typedef struct primary_credential_s *pri_cred_ptr;
typedef struct primary_credential_s pri_cred_t[1];

// end of 5.4

// end of Chapter 5

#endif
