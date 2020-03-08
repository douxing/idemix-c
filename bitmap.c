#include "idemix_bitmap.h"

void bitmap_init(bitmap_t v)
{
  mpz_init(v);
}

void bitmap_clear(bitmap_t v)
{
  mpz_clear(v);
}

void bitmap_set(bitmap_t dst, const bitmap_t src)
{
  mpz_set(dst, src);
}

void bitmap_setbit(bitmap_t v, mp_bitcnt_t i)
{
  mpz_setbit(v, i);
}

void bitmap_clrbit(bitmap_t v, mp_bitcnt_t i)
{
  mpz_clrbit(v, i);
}

// return 1(true) if the vector contains index
// return 0(flase) otherwise
int bitmap_tstbit(const bitmap_t v, mp_bitcnt_t i)
{
  return mpz_tstbit(v, i);
}

mp_bitcnt_t bitmap_scan0(const bitmap_t v, mp_bitcnt_t starting_bit)
{
  return mpz_scan0(v, starting_bit);
}

mp_bitcnt_t bitmap_scan1(const bitmap_t v, mp_bitcnt_t starting_bit)
{
  return mpz_scan1(v, starting_bit);
}

mp_bitcnt_t bitmap_cnt0(const bitmap_t v, mp_bitcnt_t end)
{
  mp_bitcnt_t cnt = 0;
  for (mp_bitcnt_t i = bitmap_scan0(v, 0); i < end; i = bitmap_scan0(v, i + 1)) {
    ++cnt;
  }
  return cnt;
}

mp_bitcnt_t bitmap_cnt1(const bitmap_t v, mp_bitcnt_t end)
{
  mp_bitcnt_t cnt = 0;
  for (mp_bitcnt_t i = bitmap_scan1(v, 0); i < end; i = bitmap_scan1(v, i + 1)) {
    ++cnt;
  }
  return cnt;
}
