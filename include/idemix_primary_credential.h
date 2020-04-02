#ifndef __IDEMIX_PRIMARY_CREDENTIAL_H__
#define __IDEMIX_PRIMARY_CREDENTIAL_H__

#include <gmp.h>
#include "idemix_schema.h"
#include "idemix_issuer_key.h"
#include "idemix_attribute.h"
#include "idemix_primary_pre_credential.h"

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
(primary_credential_t pc,
 schema_t s); // l = |Cs| in the schema

void primary_credential_clear
(primary_credential_t pr);

void primary_credential_assign
(primary_credential_t pr,
 mpz_t v_apos,
 attr_vec_t Ah,
 primary_pre_credential_t ppc);

int primary_pre_credential_verify
(primary_pre_credential_t ppc,
 issuer_pk_t pk,
 mpz_t n1,
 primary_credential_t pc);

// end of 5.4

#endif // __IDEMIX_PRIMARY_CREDENTIAL_H__
