#ifndef __IDEMIX_INDEX_VEC_H__
#define __IDEMIX_INDEX_VEC_H__

#define INDEX_VEC_INITIAL_CAPACITY 1024

struct index_vec_s {
  unsigned long next_index; // highest index + 1, initially 0
  unsigned long cap;        // = length of vec
  unsigned char *vec;       // bitmap of the index
};
typedef struct index_vec_s *index_vec_ptr;
typedef struct index_vec_s index_vec_t[1];

void index_vec_init(index_vec_t v);
void index_vec_clear(index_vec_t v);
void index_vec_clone(index_vec_t dst, index_vec_t src);

int  index_vec_is_set(const index_vec_t v,  const unsigned long index);
void index_vec_set(index_vec_t v, const unsigned long index);
void index_vec_unset(index_vec_t v, const unsigned long index);

unsigned long index_vec_next_index(const index_vec_t v);

#endif // __IDEMIX_INDEX_VEC_H__
