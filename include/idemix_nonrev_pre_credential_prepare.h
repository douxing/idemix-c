#ifndef __IDEMIX_NONREV_PRE_CREDENTIAL_PREPARE_H__
#define __IDEMIX_NONREV_PRE_CREDENTIAL_PREPARE_H__

#include <pbc/pbc.h>
#include "idemix_nonrev_key.h"

// Chapter 5:

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

void nonrev_pre_credential_prepare_clear
(nonrev_pre_credential_prepare_t nrpc_prep);

// 5.2 Holder prepares for non-revocation credential:
void nonrev_pre_credential_prepare_assign
(nonrev_pre_credential_prepare_t nrpc_prep,
 element_t s_apos,
 nonrev_pk_t pk);

// end of Chapter 5.1

#endif // __IDEMIX_NONREV_PRE_CREDENTIAL_PREPARE_H__
