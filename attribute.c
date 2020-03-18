#include <stdlib.h>
#include "idemix_random.h"
#include "idemix_utils.h"
#include "idemix_attribute.h"

void attr_vec_init(attr_vec_t av, unsigned long l)
{
  av->l = l;
  av->attrs = (attr_ptr)malloc(sizeof(attr_t) * l);
  for (unsigned long i = 0; i < l; ++i) {
    av->attrs[i].i = 0;
    mpz_inits(av->attrs[i].v, NULL);
  }
}

void attr_vec_init_random(attr_vec_t av,
			  const unsigned long l,
			  const unsigned long bits)
{
  av->l = l;
  av->attrs = (attr_ptr)malloc(sizeof(attr_t) * l);
  for (unsigned long i = 0; i < l; ++i) {
    av->attrs[i].i = 0;
    random_num_exact_bits(av->attrs[i].v, bits);
  }
}

void attr_vec_clear(attr_vec_t av)
{
  for (unsigned long i = 0; i < av->l; ++i) {
    mpz_clear(av->attrs[i].v);
  }
  free(av->attrs);
}

unsigned long attr_vec_size(attr_vec_t av)
{
  return av->l;
}

attr_ptr attr_vec_head(attr_vec_t av)
{
  return av->attrs;
}

void attr_vec_combine(attr_vec_t dst, attr_vec_t one, attr_vec_t two)
{
  unsigned long i = 0;
  unsigned long j1 = 0;
  unsigned long j2 = 0;
  unsigned long l1 = attr_vec_size(one);
  unsigned long l2 = attr_vec_size(two);
  // assert attr_vec_size(dst) = l1 + l2

  while (j1 < l1 && j2 < l2) {
    attr_ptr ap  = attr_vec_head(dst) + i;
    attr_ptr ap1 = attr_vec_head(one) + j1;
    attr_ptr ap2 = attr_vec_head(two) + j2;
    if (ap1->i < ap2->i) {
      ap->i = ap1->i;
      mpz_set(ap->v, ap1->v);
      ++j1;
    } else if (ap1->i > ap2->i) {
      ap->i = ap2->i;
      mpz_set(ap->v, ap2->v);
      ++j2;
    } else {
      // equal i???? assert false
    }
    ++i;
  }
}

// page 5 first paragraph
// Compute m2 ← H(i||H) and store information about Holder
// and the value i in a local database.
void compute_m2(mpz_t m2, unsigned long i, unsigned long H)
{
  mpz_t mi, mH;
  mpz_init_set_ui(mi, i);
  mpz_init_set_ui(mH, H);
  sm3_mpzs(m2, mi, mH);
}
