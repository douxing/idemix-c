#ifndef __IDEMIX_PRIMARY_CREDENTIAL_REQUEST_H__
#define __IDEMIX_PRIMARY_CREDENTIAL_REQUEST_H__

#include <gmp.h>
#include "idemix_schema.h"
#include "idemix_issuer_key.h"
#include "idemix_attribute.h"

// 5.1 Holder Setup:

struct primary_credential_request_s {
  mpz_t U;
  mpz_t c;
  mpz_t v_apos_caret;

  // contains hidden mi_caret
  attr_vec_t m_carets;

  mpz_t n1;
};
typedef struct primary_credential_request_s \
               *primary_credential_request_ptr;
typedef struct primary_credential_request_s \
               primary_credential_request_t[1];

void primary_credential_request_init
(primary_credential_request_t ppc_prep,
 schema_t s);

void primary_credential_request_clear
(primary_credential_request_t ppc_prep);

void primary_credential_request_assign
(primary_credential_request_t ppc_prep,
 issuer_pk_t pk,
 mpz_t n0,
 mpz_t v_apos,
 attr_vec_t Ah); // passed in by holder, so this is known here

// 0 == ok else = error
int primary_credential_request_verify
(primary_credential_request_t ppc_prep,
 issuer_pk_t pk,
 mpz_t n0);

// end of 5.1

#endif // __IDEMIX_PRIMARY_CREDENTIAL_REQUEST_H__
