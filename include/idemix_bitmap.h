#ifndef __IDEMIX_BITMAP_H__
#define __IDEMIX_BITMAP_H__

#include <gmp.h>

typedef mpz_ptr bitmap_ptr;
typedef mpz_t   bitmap_t;

void bitmap_init(bitmap_t v);
void bitmap_clear(bitmap_t v);
void bitmap_set(bitmap_t dst, bitmap_t src);

void bitmap_setbit(bitmap_t v, mp_bitcnt_t index);
void bitmap_clrbit(bitmap_t v, mp_bitcnt_t index);
int  bitmap_tstbit(const bitmap_t v, mp_bitcnt_t index);

mp_bitcnt_t bitmap_cnt0(bitmap_t v, mp_bitcnt_t end);
mp_bitcnt_t bitmap_cnt1(bitmap_t v, mp_bitcnt_t end);

#endif // __IDEMIX_BITMAP_H__
