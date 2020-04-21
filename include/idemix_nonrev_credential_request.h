#ifndef __IDEMIX_NONREV_CREDENTIAL_REQUEST_H__
#define __IDEMIX_NONREV_CREDENTIAL_REQUEST_H__

#include <pbc/pbc.h>
#include "idemix_nonrev_key.h"

// Chapter 5:

struct nonrev_credential_request_s {
  element_t U; // in G1
};
typedef struct nonrev_credential_request_s *nonrev_credential_request_ptr;
typedef struct nonrev_credential_request_s nonrev_credential_request_t[1];

void nonrev_credential_request_init
(nonrev_credential_request_t nrc_req, // OUT
 pairing_t pairing);

void nonrev_credential_request_clear
(nonrev_credential_request_t nrc_req);

// 5.2 Holder prepares for non-revocation credential:
void nonrev_credential_request_assign
(nonrev_credential_request_t nrc_req,
 element_t s_apos,
 nonrev_pk_t pk);

// end of Chapter 5.1

#endif // __IDEMIX_NONREV_CREDENTIAL_REQUEST_H__
