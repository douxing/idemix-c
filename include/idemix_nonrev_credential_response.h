#ifndef __IDEMIX_NONREV_CREDENTIAL_RESPONSE_H__
#define __IDEMIX_NONREV_CREDENTIAL_RESPONSE_H__

#include <pbc/pbc.h>
#include "idemix_nonrev_key.h"
#include "idemix_witness.h"
#include "idemix_nonrev_credential_request.h"

// Chapter 5:

// 5.3 Non-revocation Credential Issuance:

struct nonrev_credential_response_s {
  element_t IA;          // IA = z = IDa in GT
  element_t sigma;       // in G1
  element_t c;           // in Zr
  element_t s_apos_apos; // in Zr

  witness_t wit_i;

  element_t g_i;         // in G1
  element_t g_apos_i;    // in G2
  unsigned long i;
};
typedef struct nonrev_credential_response_s \
               *nonrev_credential_response_ptr;
typedef struct nonrev_credential_response_s \
               nonrev_credential_response_t[1];

void nonrev_credential_response_init
(nonrev_credential_response_t nrc_res, // OUT
 pairing_t pairing);

void nonrev_credential_response_clear
(nonrev_credential_response_t nrpc); // OUT

void nonrev_credential_response_assign
(nonrev_credential_response_t nrc_res,
 mpz_t m2,
 unsigned long i,
 nonrev_pk_t pk,
 nonrev_sk_t sk,
 accumulator_t acc,
 accumulator_pk_t acc_pk,
 accumulator_sk_t acc_sk,
 nonrev_credential_request_t nrc_req);

// end of 5.3

#endif // __IDEMIX_NONREV_CREDENTIAL_RESPONSE_H__
