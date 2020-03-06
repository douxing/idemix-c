#ifndef __IDEMIX_SCHEMA_H__
#define __IDEMIX_SCHEMA_H__

#include <gmp.h>

struct attribute_s {
  mpz_t m; // 256-bit, if not used, set this to 0

  // used in Chapter 5 (in between Issuer and Holder)
  // 0 = known, 1 = hidden
  unsigned long is_hidden;

  // used in Chapter 7 (in between Verifer and Prover)
  // 0 if it is revealed, one of x1 open attributes
  // in [1, x4], it is hidden and in an equivalence class
  unsigned long eq_class;
};
typedef struct attribute_s *attribute_ptr;
typedef struct attribute_s attribute_t[1];

// schema template
// this can be used:
// Chapter 5: in between Issuer and Holder
// Chapter 7: in between Verifier and Prover
struct schema_s {
  unsigned long l;
  attribute_ptr vec;
};
typedef struct schema_s *schema_ptr;
typedef struct schema_s schema_t[1];

void schema_init(schema_t schema, const unsigned long l);

// used in Chapter 5
unsigned long schema_attr_is_hidden(schema_t s, const unsigned long i);

// used in Chapter 7
unsigned long schema_attr_is_revealed(schema_t s, const unsigned long i);
unsigned long schema_attr_eq_class(schema_t s, const unsigned long i);



#endif
