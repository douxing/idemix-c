#include "idemix_utils.h"

#include <pbc/pbc.h> // gmp.h included
#include <stdarg.h>

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
