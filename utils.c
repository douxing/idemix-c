#include "idemix_utils.h"

#include <pbc/pbc.h> // gmp.h included
#include <stdarg.h>

#define BUF_SIZE 512 // make sure it is big

void sm3_mpzs(mpz_ptr dest, mpz_ptr n, ...)
{
  unsigned char buf[BUF_SIZE] = { 0 };
  size_t count;
  sm3_ctx_t ctx;
  sm3_init(&ctx);

  va_list ap;
  va_start(ap, n);
  do {
    // TODO: call mpz_to_sm3_buf
    mpz_export(buf, &count, 1, 1, 1, 0, n);
    sm3_update(&ctx, buf, count);
    n = va_arg(ap, mpz_ptr);
  } while(n != NULL);
  va_end (ap);

  unsigned char h[SM3_DIGEST_LENGTH] = { 0 };
  sm3_final(&ctx, h);

  // TODO: call sm3_buf_to_mpz
  mpz_import(dest, SM3_DIGEST_LENGTH, 1, 1, 1, 0, h);
}

void sm3_TCn1(mpz_ptr dst, mpz_vec_t T, mpz_vec_t C, mpz_t n1)
{
  unsigned char buf[BUF_SIZE] = { 0 };
  size_t count;
  sm3_ctx_t ctx;
  sm3_init(&ctx);

  for (unsigned long i = 0; i < mpz_vec_size(T); ++i) {
    mpz_ptr p = mpz_vec_head(T) + i;
    mpz_export(buf, &count, 1, 1, 1, 0, p);
    sm3_update(&ctx, buf, count);
  }

  for (unsigned long i = 0; i < mpz_vec_size(C); ++i) {
    mpz_ptr p = mpz_vec_head(C) + i;
    mpz_export(buf, &count, 1, 1, 1, 0, p);
    sm3_update(&ctx, buf, count);
  }

  mpz_export(buf, &count, 1, 1, 1, 0, n1);
  sm3_update(&ctx, buf, count);  

  unsigned char h[SM3_DIGEST_LENGTH] = { 0 };
  sm3_final(&ctx, h);

  mpz_import(dst, SM3_DIGEST_LENGTH, 1, 1, 1, 0, h);
}

void decompose_to_4_squares(mpz_t u[4], // OUT
			    mpz_t delta)
{
  // TODO: ...
  (void)delta;
  (void)u;
}
