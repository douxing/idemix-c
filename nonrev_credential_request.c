#include "idemix_nonrev_credential_request.h"

void nonrev_credential_request_init
(nonrev_credential_request_t nrc_req,
 pairing_t pairing)
{
  element_init_G1(nrc_req->U, pairing);
}

void nonrev_credential_request_clear
(nonrev_credential_request_t nrc_req)
{
  element_clear(nrc_req->U);
}

// 5.2 Holder prepares for non-revocation credential:
void nonrev_credential_request_assign
(nonrev_credential_request_t nrc_req,
 element_t s_apos,
 nonrev_pk_t pk)
{
  element_pow_zn(nrc_req->U, pk->h2, s_apos);
}
