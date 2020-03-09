#include <stdlib.h>

#include "idemix_mpz_vec.h"

void mpz_vec_init(mpz_vec_t v)
{
  v->next_index = 0;
  v->cap = MPZ_VEC_INITIAL_CAPACITY;
  v->vec = (mpz_ptr)malloc(sizeof(mpz_t) * v->cap);
}

void mpz_vec_clear(mpz_vec_t v)
{
  free(v->vec);
}

void mpz_vec_append(mpz_vec_t v, mpz_t val)
{
  if (v->cap <= v->next_index) {
    unsigned long cap = v->cap * 2 + 1;
    mpz_ptr vec = (mpz_ptr)malloc(sizeof(mpz_t) * cap);

    for (unsigned long i = 0; i < v->cap; ++i) {
      // TODO: memory handler?
      mpz_init(vec + i);
      mpz_set(vec + i, v->vec + i);
      mpz_clear(v->vec + i);
    }

    v->cap = cap;
    free(v->vec);
    v->vec = vec;
  }

  mpz_init_set(v->vec + v->next_index, val);
  ++v->next_index;
}

mpz_ptr mpz_vec_head(mpz_vec_t v)
{
  return v->vec;
}

unsigned long mpz_vec_size(mpz_vec_t v)
{
  return v->next_index;
}

