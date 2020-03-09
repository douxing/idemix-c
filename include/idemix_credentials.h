 #ifndef __IDEMIX_CREDENTIALS_H__
#define __IDEMIX_CREDENTIALS_H__

#include "idemix_utils.h"
#include "idemix_crypto.h"
#include "idemix_schema.h"
#include "idemix_attribute.h"
#include "idemix_witness.h"

// Chapter 5:

// 5.1 Holder Setup:

struct primary_pre_credential_prepare_s {
  mpz_t U;
  mpz_t c;
  mpz_t v_apos_caret;

  // contains hidden mi_caret
  attr_vec_t m_carets;

  mpz_t n1;
};
typedef struct primary_pre_credential_prepare_s \
               *primary_pre_credential_prepare_ptr;
typedef struct primary_pre_credential_prepare_s \
               primary_pre_credential_prepare_t[1];

void primary_pre_credential_prepare_init
(primary_pre_credential_prepare_t ppc_prep,
 schema_t s);

struct nonrev_pre_credential_prepare_s {
  element_t U; // in G1
};
typedef struct nonrev_pre_credential_prepare_s \
               *nonrev_pre_credential_prepare_ptr;
typedef struct nonrev_pre_credential_prepare_s \
               nonrev_pre_credential_prepare_t[1];

void nonrev_pre_credential_prepare_init
(nonrev_pre_credential_prepare_t nrpc_prep, // OUT
 pairing_t pairing);

// end of Chapter 5.1

// 5.2 Primary Credential Issurance:

struct primary_pre_credential_s {
  attr_vec_t Ak; // only contains known mi

  mpz_t A;
  mpz_t e;
  mpz_t v_apos_apos;
  mpz_t s_e;
  mpz_t c_apos;
};
typedef struct primary_pre_credential_s \
               *primary_pre_credential_ptr;
typedef struct primary_pre_credential_s \
               primary_pre_credential_t[1];

void primary_pre_credential_init
(primary_pre_credential_t ppc,
 schema_t s);

// end of 5.2

// 5.3 Non-revocation Credential Issuance:

struct nonrev_pre_credential_s {
  element_t IA;          // IA = z = IDa in GT
  element_t sigma;       // in G1
  element_t c;           // in Zr
  element_t s_apos_apos; // in Zr

  witness_t wit_i;

  element_t g_i;         // in G1
  element_t g_apos_i;    // in G2
  unsigned long i;
};
typedef struct nonrev_pre_credential_s \
               *nonrev_pre_credential_ptr;
typedef struct nonrev_pre_credential_s \
               nonrev_pre_credential_t[1];

void nonrev_pre_credential_init(nonrev_pre_credential_t nrpc, // OUT
				pairing_t pairing);

// end of 5.3

// 5.4 Storing Credentials

struct primary_credential_s {
  attr_vec_t Cs; // contains all attributes in a credential shema
  
  mpz_t e;
  mpz_t A;
  mpz_t v;
};
typedef struct primary_credential_s *primary_credential_ptr;
typedef struct primary_credential_s primary_credential_t[1];

void primary_credential_init
(primary_credential_t pr,
 schema_t s);

struct nonrev_credential_s {
  element_t IA;       // IA = z = IDa in GT
  element_t sigma;    // in G1
  element_t c;        // in Zr
  element_t s;        // in Zr
  
  witness_t wit_i;

  element_t g_i;      // in G1
  element_t g_apos_i; // in G2
  unsigned long i;
};
typedef struct nonrev_credential_s *nonrev_credential_ptr;
typedef struct nonrev_credential_s nonrev_credential_t[1];

void nonrev_credential_init(nonrev_credential_t nrc, pairing_t pairing);

void nonrev_credential_update
(nonrev_credential_t nrc, // nrc->wit_i->V as V_old
 accumulator_t acc); // latest accumulator

// end of 5.4

// end of Chapter 5

#endif
