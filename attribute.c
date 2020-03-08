#include <stdlib.h>
#include "idemix_random.h"
#include "idemix_attribute.h"

void attr_vec_init(attr_vec_t av, unsigned long l)
{
  av->l = l;
  av->attrs = (attr_ptr)malloc(sizeof(attr_t) * l);
  for (unsigned long i = 0; i < l; ++i) {
    av->attrs[i].i = 0;
    mpz_inits(av->attrs[i].v);
  }
}

void attr_vec_clear(attr_vec_t av)
{
  for (unsigned long i = 0; i < av->l; ++i) {
    mpz_clears(av->attrs[i].v);
  }
  free(av->attrs);
}

unsigned long attr_vec_size(attr_vec_t av)
{
  return av->l;
}

attr_ptr attr_vec_attr_ptr(attr_vec_t av)
{
  return av->attrs;
}
