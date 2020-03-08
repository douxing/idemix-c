#include "idemix_index_vec.h"

void (*index_vec_init) (index_vec_t)              = bitmap_init;
void (*index_vec_clear)(index_vec_t)              = bitmap_clear;
void (*index_vec_set)  (index_vec_t, index_vec_t) = bitmap_set;

void (*index_vec_setbit)(index_vec_t, mp_bitcnt_t)       = bitmap_setbit;
void (*index_vec_clrbit)(index_vec_t, mp_bitcnt_t)       = bitmap_clrbit;
int  (*index_vec_tstbit)(const index_vec_t, mp_bitcnt_t) = bitmap_tstbit;

mp_bitcnt_t (*index_vec_cnt0)(index_vec_t, mp_bitcnt_t) = bitmap_cnt0;
mp_bitcnt_t (*index_vec_cnt1)(index_vec_t, mp_bitcnt_t) = bitmap_cnt1;

