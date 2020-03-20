// @copy https://github.com/AyrA/sm3
#ifndef __IDEMIX_SM3_H__
#define __IDEMIX_SM3_H__

#define SM3_DIGEST_LENGTH	32
#define SM3_BLOCK_SIZE		64

#include <sys/types.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint32_t digest[8];
	int nblocks;
	unsigned char block[64];
	int num;
} sm3_ctx_t;

void sm3_init(sm3_ctx_t *ctx);
void sm3_update(sm3_ctx_t *ctx, const unsigned char* data, size_t data_len);
void sm3_final(sm3_ctx_t *ctx, unsigned char digest[SM3_DIGEST_LENGTH]);
void sm3_compress(uint32_t digest[8], const unsigned char block[SM3_BLOCK_SIZE]);
void sm3(const unsigned char *data, size_t datalen, unsigned char digest[SM3_DIGEST_LENGTH]);

#include "idemix_mpz_vec.h"

void sm3_mpzs(mpz_ptr dest, mpz_ptr n, ...);
void sm3_TCn(mpz_ptr dst, mpz_vec_t T, mpz_vec_t C, mpz_t n1);

#ifdef __cplusplus
}
#endif
#endif // __IDEMIX_SM3_H__
