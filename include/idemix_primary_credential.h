#ifndef __IDEMIX_PRIMARY_CREDENTIAL_H__
#define __IDEMIX_PRIMARY_CREDENTIAL_H__

#include <gmp.h>
#include "idemix_schema.h"
#include "idemix_attribute.h"

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

// end of 5.1

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

// 5.4 Storing Credentials

struct primary_credential_s {
  attr_vec_t Cs; // contains all attributes in a credential shema
  
  mpz_t e;
  mpz_t A;
  mpz_t v;
};
typedef struct primary_credential_s *primary_credential_ptr;
typedef struct primary_credential_s primary_credential_t[1];

void primary_credential_init_assign
(primary_credential_t pr,
 unsigned long l); // l = |Cs| in the schema

// end of 5.4

#endif // __IDEMIX_PRIMARY_CREDENTIAL_H__
