#ifndef __IDEMIX_PRIMARY_CREDENTIAL_RESPONSE_H__
#define __IDEMIX_PRIMARY_CREDENTIAL_RESPONSE_H__

#include <gmp.h>
#include "idemix_schema.h"
#include "idemix_issuer_key.h"
#include "idemix_attribute.h"
#include "idemix_primary_credential_request.h"

// 5.2 Primary Credential Issurance:

struct primary_credential_response_s {
  attr_vec_t Ak; // only contains known mi

  mpz_t A;
  mpz_t e;
  mpz_t v_apos_apos;
  mpz_t s_e;
  mpz_t c_apos;
};
typedef struct primary_credential_response_s *primary_credential_response_ptr;
typedef struct primary_credential_response_s primary_credential_response_t[1];

void primary_credential_response_init
(primary_credential_response_t ppc,
 schema_t s);

void primary_credential_response_clear
(primary_credential_response_t ppc);
// end of 5.2

void primary_credential_response_assign
(primary_credential_response_t ppc,
 issuer_pk_t pk,
 issuer_sk_t sk,
 attr_vec_t Ak,
 primary_credential_request_t ppc_prep);

#endif // __IDEMIX_PRIMARY_CREDENTIAL_RESPONSE_H__
