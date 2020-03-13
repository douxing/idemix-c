#ifndef __IDEMIX_PRIMARY_PRE_CREDENTIAL_H__
#define __IDEMIX_PRIMARY_PRE_CREDENTIAL_H__

#include <gmp.h>
#include "idemix_schema.h"
#include "idemix_issuer_key.h"
#include "idemix_attribute.h"
#include "idemix_primary_pre_credential_prepare.h"

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

void primary_pre_credential_clear
(primary_pre_credential_t ppc);
// end of 5.2

void primary_pre_credential_assign
(primary_pre_credential_t ppc,
 issuer_pk_t pk,
 issuer_sk_t sk,
 primary_pre_credential_prepare_t ppc_prep);

#endif // __IDEMIX_PRIMARY_PRE_CREDENTIAL_H__
