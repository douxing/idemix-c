#ifndef __IDEMIX_SCHEMA_H__
#define __IDEMIX_SCHEMA_H__

#include <gmp.h>
#include "idemix_bitmap.h"

/* struct attribute_property_s { */
/*   mpz_t m; // 256-bit, if not used, set this to 0 */

/*   // used in Chapter 5 (in between Issuer and Holder) */
/*   // 0 = known, 1 = hidden */
/*   unsigned long is_hidden; */

/*   // used in Chapter 7 (in between Verifer and Prover) */
/*   // 0 if it is revealed, one of x1 open attributes */
/*   // in [1, x4], it is hidden and in an equivalence class */
/*   unsigned long eq_class; */
/* }; */
/* typedef struct attribute_s *attribute_ptr; */
/* typedef struct attribute_s attribute_t[1]; */

// schema template
struct schema_s {
  unsigned long l; // total number of the attributes

  // bitmap for flags
  // this can be used:
  // Chapter 5: in between Holder and Issuer
  //            flag means attribute is hidden to issuer
  //            hidden = 1, known = 0
  // Chapter 7: in between Prover and Verifier
  //            flag means attribute is revealed to verifier
  //            hidden = 1, revealed = 0
  bitmap_t map;
};
typedef struct schema_s *schema_ptr;
typedef struct schema_s schema_t[1];

void schema_init(schema_t s, const unsigned long i);
void schema_clear(schema_t s);

int schema_attr_is_hidden(schema_t s, unsigned long i);
void schema_attr_set_hidden(schema_t s, unsigned long i);
unsigned long schema_attr_cnt_hidden(schema_t s);

// below two functions are the same:
void schema_attr_set_known(schema_t s, unsigned long i);
void schema_attr_set_revealed(schema_t s, unsigned long i);

// below two functions means the same:
unsigned long schema_attr_cnt_known(schema_t s);
unsigned long schema_attr_cnt_revealed(schema_t s);

// void schema_init(schema_t schema, const unsigned long l);

// used in both Chapter 5 and Chapter 7
// unsigned long schema_attr_is_hidden(schema_t s, const unsigned long i);

#endif
