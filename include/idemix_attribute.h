#ifndef __IDEMIX_ATTRIBUTE_H__
#define __IDEMIX_ATTRIBUTE_H__

#include <gmp.h>
#include "idemix_schema.h"

struct attribute_s {
  // subscript index of the m_i or m_j alike
  unsigned long i;
                   

  // can represent many attributes
  // as m:       value it self
  // as m_tilde: random number in 5.1 - 2 or 7.2 - Validity proof - 1
  // as m_caret: Eq. (8)
  mpz_t v;
};
typedef struct attribute_s *attr_ptr;
typedef struct attribute_s attr_t[1];

// dx: no encapsulation of attribute for ease of use
void attribute_init(attr_t a);


struct attribute_vec_s {
  // number of attributes
  // in 5.1 primary pre-credential prepare - 6
  // l = |Ah|
  // in 5.2 primary pre-credential - 7
  // l = |Ak|
  // in 5.4 primary credential - 7
  // l = |Cs| = |Ah| + |Ak|
  unsigned long l;

  attr_ptr attrs;
};
typedef struct attribute_vec_s *attr_vec_ptr;
typedef struct attribute_vec_s attr_vec_t[1];

void attr_vec_init(attr_vec_t av, unsigned long l);
void attr_vec_clear(attr_vec_t av);

void attr_vec_init_random(attr_vec_t av,
			  const unsigned long l,
			  const unsigned long bits);

unsigned long attr_vec_size(attr_vec_t av);
attr_ptr attr_vec_head(attr_vec_t av);

void attr_vec_set(attr_vec_t dst, attr_vec_t src);
void attr_vec_combine(attr_vec_t dst, attr_vec_t one, attr_vec_t two);

// page 5 first paragraph
// Compute m2 ← H(i||H) and store information about Holder
// and the value i in a local database.
void compute_m2(mpz_ptr m2, mpz_ptr i, mpz_ptr H);

#endif // __IDEMIX_ATTRIBUTE_H__
