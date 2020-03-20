// @copy https://github.com/AyrA/sm3
#include "idemix_sm3.h"
#include "idemix_byteorder.h"
#include <string.h>
#include <stdarg.h>

void sm3_init(sm3_ctx_t *ctx)
{
	ctx->digest[0] = 0x7380166F;
	ctx->digest[1] = 0x4914B2B9;
	ctx->digest[2] = 0x172442D7;
	ctx->digest[3] = 0xDA8A0600;
	ctx->digest[4] = 0xA96F30BC;
	ctx->digest[5] = 0x163138AA;
	ctx->digest[6] = 0xE38DEE4D;
	ctx->digest[7] = 0xB0FB0E4E;
	
	ctx->nblocks = 0;
	ctx->num = 0;
}

void sm3_update(sm3_ctx_t *ctx, const unsigned char* data, size_t data_len)
{
	if (ctx->num) {
		unsigned int left = SM3_BLOCK_SIZE - ctx->num;
		if (data_len < left) {
			memcpy(ctx->block + ctx->num, data, data_len);
			ctx->num += data_len;
			return;
		} else {
			memcpy(ctx->block + ctx->num, data, left);
			sm3_compress(ctx->digest, ctx->block);
			ctx->nblocks++;
			data += left;
			data_len -= left;
		}
	}
	while (data_len >= SM3_BLOCK_SIZE) {
		sm3_compress(ctx->digest, data);
		ctx->nblocks++;
		data += SM3_BLOCK_SIZE;
		data_len -= SM3_BLOCK_SIZE;
	}
	ctx->num = data_len;
	if (data_len) {
		memcpy(ctx->block, data, data_len);
	}
}

void sm3_final(sm3_ctx_t *ctx, unsigned char *digest)
{
	unsigned int i;
	uint32_t *pdigest = (uint32_t *)digest;
	uint32_t *count = (uint32_t *)(ctx->block + SM3_BLOCK_SIZE - 8);
		
	ctx->block[ctx->num] = 0x80;
	
	if (ctx->num + 9 <= SM3_BLOCK_SIZE) {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 9);
	} else {
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 1);
		sm3_compress(ctx->digest, ctx->block);
		memset(ctx->block, 0, SM3_BLOCK_SIZE - 8);
	}

	count[0] = cpu_to_be32((ctx->nblocks) >> 23);
	count[1] = cpu_to_be32((ctx->nblocks << 9) + (ctx->num << 3));
	
	sm3_compress(ctx->digest, ctx->block);
	for (i = 0; i < sizeof(ctx->digest)/sizeof(ctx->digest[0]); i++) {
		pdigest[i] = cpu_to_be32(ctx->digest[i]);
	}
}

#define ROTATELEFT(X,n)  (((X)<<(n)) | ((X)>>(32-(n))))

#define P0(x) ((x) ^  ROTATELEFT((x),9)  ^ ROTATELEFT((x),17)) 
#define P1(x) ((x) ^  ROTATELEFT((x),15) ^ ROTATELEFT((x),23)) 

#define FF0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )


void sm3_compress(uint32_t digest[8], const unsigned char block[64])
{
	int j;
	uint32_t W[68], W1[64];
	const uint32_t *pblock = (const uint32_t *)block;
	
	uint32_t A = digest[0];
	uint32_t B = digest[1];
	uint32_t C = digest[2];
	uint32_t D = digest[3];
	uint32_t E = digest[4];
	uint32_t F = digest[5];
	uint32_t G = digest[6];
	uint32_t H = digest[7];
	uint32_t SS1,SS2,TT1,TT2,T[64];

	for (j = 0; j < 16; j++) {
		W[j] = cpu_to_be32(pblock[j]);
	}
	for (j = 16; j < 68; j++) {
		W[j] = P1( W[j-16] ^ W[j-9] ^ ROTATELEFT(W[j-3],15)) ^ ROTATELEFT(W[j - 13],7 ) ^ W[j-6];;
	}
	for( j = 0; j < 64; j++) {
		W1[j] = W[j] ^ W[j+4];
	}

	for(j =0; j < 16; j++) {

		T[j] = 0x79CC4519;
		SS1 = ROTATELEFT((ROTATELEFT(A,12) + E + ROTATELEFT(T[j],j)), 7); 
		SS2 = SS1 ^ ROTATELEFT(A,12);
		TT1 = FF0(A,B,C) + D + SS2 + W1[j];
		TT2 = GG0(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTATELEFT(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTATELEFT(F,19);
		F = E;
		E = P0(TT2);
	}

	for(j =16; j < 64; j++) {

		T[j] = 0x7A879D8A;
		SS1 = ROTATELEFT((ROTATELEFT(A,12) + E + ROTATELEFT(T[j],j)), 7); 
		SS2 = SS1 ^ ROTATELEFT(A,12);
		TT1 = FF1(A,B,C) + D + SS2 + W1[j];
		TT2 = GG1(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTATELEFT(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTATELEFT(F,19);
		F = E;
		E = P0(TT2);
	}

	digest[0] ^= A;
	digest[1] ^= B;
	digest[2] ^= C;
	digest[3] ^= D;
	digest[4] ^= E;
	digest[5] ^= F;
	digest[6] ^= G;
	digest[7] ^= H;
}

void sm3(const unsigned char *msg, size_t  msglen, unsigned char dgst[SM3_DIGEST_LENGTH])
{
	sm3_ctx_t ctx;

	sm3_init(&ctx);
	sm3_update(&ctx, (void *)msg, msglen);
	sm3_final(&ctx, dgst);

	memset(&ctx, 0, sizeof(sm3_ctx_t));
}

// dx: supplimentary sm3 functions

#define BUF_SIZE 1024 // make sure it is big

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

void sm3_TCn(mpz_ptr dst, mpz_vec_t T, mpz_vec_t C, mpz_t n1)
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
