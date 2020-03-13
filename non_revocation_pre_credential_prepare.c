#include "idemix_non_revocation_pre_credential_prepare.h"

void nonrev_pre_credential_prepare_init
(nonrev_pre_credential_prepare_t nrpc_prep,
 pairing_t pairing)
{
  element_init_G1(nrpc_prep->U, pairing);
}

void nonrev_pre_credential_prepare_clear
(nonrev_pre_credential_prepare_t nrpc_prep)
{
  element_clear(nrpc_prep->U);
}

// 5.2 Holder prepares for non-revocation credential:
void nonrev_pre_credential_prepare_assign
(nonrev_pre_credential_prepare_t nrpc_prep,
 element_t s_apos,
 nonrev_pk_t pk)
{
  element_pow_zn(nrpc_prep->U, pk->h2, s_apos);
}
