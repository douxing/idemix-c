#ifndef __IDEMIX_ATTRIBUTE_H__
#define __IDEMIX_ATTRIBUTE_H__

#include <gmp.h>

struct attribute_s {
  unsigned long i; // subscript index of the m_i or m_j alike

  // can represent many attributes
  // as m:       value it self
  // as m_tilde: random number in 5.1 - 2 or 7.2 - Validity proof - 1
  // as m_caret: Eq. (8)
  mpz_t v;
};
typedef struct attribute_s *attr_ptr;
typedef struct attribute_s attr_t[1];

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
void attr_vec_init_with_random(attr_vec_t av,
			       const unsigned long l,
			       const unsigned long bits);
void attr_vec_clear(attr_vec_t av);

unsigned long attr_vec_size(attr_vec_t av);
attr_ptr attr_vec_head(attr_vec_t av);

void gen_random_m_tilde(attr_vec_t av, unsigned long bits);

#endif // __IDEMIX_ATTRIBUTE_H__
