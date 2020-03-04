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
  element_t IA;          // IA = z = IDa in GT
  element_t sigma;       // in G1
  element_t c;           // in Zr
  element_t s_apos_apos; // in Zr

  witness_t wit_i;

  element_t g_i;         // in G1
  element_t g_apos_i;    // in G2
  unsigned long i;
};
typedef struct non_revok_pre_credential_s *nr_pre_cred_ptr;
typedef struct non_revok_pre_credential_s nr_pre_cred_t[1];

void non_revok_pre_credential_init(nr_pre_cred_t nrpc, // OUT
				   pairing_t pairing);

// end of 5.3

// 5.4 Storing Credentials

struct primary_credential_s {
  mpz_t m1; // link secret, the only elmenet in As
  mpz_t e;
  mpz_t A;
  mpz_t v;
};
typedef struct primary_credential_s *pri_cred_ptr;
typedef struct primary_credential_s pri_cred_t[1];

void primary_credential_init(pri_cred_t pr);

struct non_revok_credential_s {
  element_t IA;       // IA = z = IDa in GT
  element_t sigma;    // in G1
  element_t c;        // in Zr
  element_t s;        // in Zr
  
  witness_t wit_i;

  element_t g_i;      // in G1
  element_t g_apos_i; // in G2
  unsigned long i;
};
typedef struct non_revok_credential_s *nr_cred_ptr;
typedef struct non_revok_credential_s nr_cred_t[1];

void non_revok_credential_init(nr_cred_t nrc, pairing_t pairing);

void non_revok_credential_update
(nr_cred_t nrc, // cnr->wit_i->V as V_old
 index_vec_t V, // new V
 accumulator_t acc,
 const unsigned long L);

// end of 5.4

// end of Chapter 5

#endif
