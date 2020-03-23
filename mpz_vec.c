#include <stdlib.h>

#include "idemix_mpz_vec.h"

void mpz_vec_init(mpz_vec_t v)
{
  v->next = 0;
  v->cap = MPZ_VEC_INITIAL_CAPACITY;
  v->v = (mpz_ptr)malloc(sizeof(mpz_t) * v->cap);
  // dx: lazy mpz_init
}

void mpz_vec_clear(mpz_vec_t v)
{
  for (unsigned long i = 0; i < v->next; ++i) {
    mpz_clear(v->v + i);
  }
  free(v->v);
}

void mpz_vec_append(mpz_vec_t v, const mpz_t val)
{
  if (v->cap <= v->next) {
    unsigned long cap = v->cap * 2 + 1;
    mpz_ptr vec = (mpz_ptr)malloc(sizeof(mpz_t) * cap);

    for (unsigned long i = 0; i < v->cap; ++i) {
      // TODO: memory handler?
      mpz_init(vec + i);
      mpz_swap(vec + i, v->v + i);
      mpz_clear(v->v + i);
    }

    v->cap = cap;
    free(v->v);
    v->v = vec;
  }

  mpz_init_set(v->v + v->next, val);
  ++v->next;
}

mpz_ptr mpz_vec_head(mpz_vec_t v)
{
  return v->v;
}

unsigned long mpz_vec_size(mpz_vec_t v)
{
  return v->next;
}
