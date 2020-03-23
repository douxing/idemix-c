#ifndef __IDEMIX_NONREV_PRE_CREDENTIAL_H__
#define __IDEMIX_NONREV_PRE_CREDENTIAL_H__

#include <pbc/pbc.h>
#include "idemix_nonrev_key.h"
#include "idemix_witness.h"
#include "idemix_nonrev_pre_credential_prepare.h"

// Chapter 5:

// 5.3 Non-revocation Credential Issuance:

struct nonrev_pre_credential_s {
  element_t IA;          // IA = z = IDa in GT
  element_t sigma;       // in G1
  element_t c;           // in Zr
  element_t s_apos_apos; // in Zr

  witness_t wit_i;

  element_t g_i;         // in G1
  element_t g_apos_i;    // in G2
  unsigned long i;
};
typedef struct nonrev_pre_credential_s \
               *nonrev_pre_credential_ptr;
typedef struct nonrev_pre_credential_s \
               nonrev_pre_credential_t[1];

void nonrev_pre_credential_init(nonrev_pre_credential_t nrpc, // OUT
				pairing_t pairing);

void nonrev_pre_credential_clear
(nonrev_pre_credential_t nrpc); // OUT

void nonrev_pre_credential_assign
(nonrev_pre_credential_t nrpc,
 mpz_t m2,
 unsigned long i,
 nonrev_pk_t pk,
 nonrev_sk_t sk,
 accumulator_t acc,
 accumulator_pk_t acc_pk,
 accumulator_sk_t acc_sk,
 nonrev_pre_credential_prepare_t nrpc_prep);

// end of 5.3

int nonrev_pre_credential_verify
(const nonrev_pre_credential_t nrpc,
 const mpz_t v_apos);

#endif // __IDEMIX_NONREV_PRE_CREDENTIAL_H__
