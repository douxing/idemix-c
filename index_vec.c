#include <stdlib.h>
#include <memory.h>
#include "idemix_index_vec.h"

void index_vec_init(index_vec_t v)
{
  v->next_index = 0;
  v->cap = INDEX_VEC_INITIAL_CAPACITY / 8;
  v->vec = (unsigned char *)malloc(sizeof(unsigned char) * v->cap);
  memset(v->vec, 0, v->cap);
}

void index_vec_clear(index_vec_t v)
{
  free(v->vec);
}

void index_vec_clone(index_vec_t dst, index_vec_t src)
{
  if (dst->cap < src->cap) {
    free(dst->vec);
    dst->vec = (unsigned char *)malloc(sizeof(unsigned char) * src->cap);
  }

  dst->next_index = src->next_index;
  dst->cap = src->cap;
  memcpy(dst->vec, src->vec, dst->cap);
}

// return 1(true) if the vector contains index
// return 0(flase) otherwise
int index_vec_is_set(const index_vec_t v, const unsigned long i)
{
  if (v->next_index <= i) {
    return 0; // already unset
  }

  unsigned long byte_offset = i / 8;
  unsigned long bit_offset  = i % 8;
  
  return (v->vec[byte_offset] >> bit_offset) & 0x1;
}

void index_vec_set(index_vec_t v, const unsigned long i)
{
  unsigned long cap = i / 8 + 1;
  if (v->cap < cap) {
    // allocate more memory
    cap = cap * 2 + 1;
    unsigned char *vec = (unsigned char *)malloc(sizeof(unsigned char) * cap);
    memcpy(vec, v->vec, v->cap);
    memset(vec + v->cap, 0, cap - v->cap);
    v->cap = cap;
    free(v->vec);
    v->vec = vec;
  }

  unsigned long byte_offset = i / 8;
  unsigned long bit_offset  = i % 8;
  
  v->vec[byte_offset] |= 1 << bit_offset;
}

void index_vec_unset(index_vec_t v, const unsigned long i)
{
  unsigned long cap = i / 8 + 1;
  if (v->cap < cap) {
    return; // already unset
  }

  unsigned long byte_offset = i / 8;
  unsigned long bit_offset  = i % 8;

  v->vec[byte_offset] &= ~(1 << bit_offset);
}
