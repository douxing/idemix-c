#ifndef __IDEMIX_NONREV_CREDENTIAL_H__
#define __IDEMIX_NONREV_CREDENTIAL_H__

#include <pbc/pbc.h>

#include "idemix_schema.h"
#include "idemix_attribute.h"
#include "idemix_witness.h"
#include "idemix_accumulator.h"
#include "idemix_nonrev_key.h"
#include "idemix_nonrev_pre_credential.h"

// Chapter 5:


// 5.4 Storing Credentials

struct nonrev_credential_s {
  element_t IA;       // IA = z = IDa in GT
  element_t sigma;    // in G1
  element_t c;        // in Zr
  element_t s;        // in Zr
  
  witness_t wit_i;

  element_t g_i;      // in G1
  element_t g_apos_i; // in G2
  unsigned long i;
};
typedef struct nonrev_credential_s *nonrev_credential_ptr;
typedef struct nonrev_credential_s nonrev_credential_t[1];

void nonrev_credential_init(nonrev_credential_t nrc, pairing_t pairing);
void nonrev_credential_clear(nonrev_credential_t nrc);

void nonrev_credential_assign
(nonrev_credential_t nrc,
 element_t s_apos,
 nonrev_pre_credential_t nrpc);

// end of 5.4

// 7.2 Non-revocation proof Prover: 4. Update Cnr
void nonrev_credential_update
(nonrev_credential_t nrc, // nrc->wit_i->V as V_old
 accumulator_t acc); // latest accumulator


// end of Chapter 5

#endif // __IDEMIX_NONREV_CREDENTIAL_H__
