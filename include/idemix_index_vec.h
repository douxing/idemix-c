#ifndef __IDEMIX_INDEX_VEC_H__
#define __IDEMIX_INDEX_VEC_H__

#include <gmp.h>
#include "idemix_bitmap.h"

typedef bitmap_ptr index_vec_ptr;
typedef bitmap_t   index_vec_t;

void (*index_vec_init)  (index_vec_t);
void (*index_vec_clear) (index_vec_t);
void (*index_vec_set)   (index_vec_t, index_vec_t);

void (*index_vec_setidx) (index_vec_t, mp_bitcnt_t);
void (*index_vec_clridx) (index_vec_t, mp_bitcnt_t);
int  (*index_vec_tstidx) (const index_vec_t, mp_bitcnt_t);

mp_bitcnt_t (*index_vec_cnt0) (index_vec_t, mp_bitcnt_t);
mp_bitcnt_t (*index_vec_cnt1) (index_vec_t, mp_bitcnt_t);

#endif // __IDEMIX_INDEX_VEC_H__
