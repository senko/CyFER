#include <stdlib.h>
#include <string.h>
#include <sha256.h>


/* constants and transformations */

static const u32 iv[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const u32 K[64] = {
   0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
   0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
   0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
   0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
   0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
   0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
   0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
   0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

#define rotl(t,s) (((t) << s) | ((t) >> (32 - s)))
#define rotr(t,s) (((t) >> s) | ((t) << (32 - s)))
#define Ch(x,y,z) ((x & y) ^ (~x & z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22))
#define Sigma1(x) (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25))
#define sigma0(x) (rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3))
#define sigma1(x) (rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10))

/* implementation */

static void sha256_compress_block(SHA256_CTX *ctx, bool last)
{
	u32 x[64], h[8];
	u32 t1, t2;
	size_t j;
	size_t len = ctx->buflen;
	u8 *source = ctx->buffer;

	ctx->length += len * 8; 

	if (last) {
		source[len++] = 128;
		if (len > 56) {
			for (j = len; j < 128; j++) source[j] = 0;
			len = 128;
		} else {
			while (len % 64) source[len++] = 0;
		}
		len -= 8;

		big_store32((u32) (ctx->length >> 32), source + len); len += 4;
		big_store32((u32) ctx->length, source + len); len += 4;
	}
	len /= 64;

	while (len) {
		for (j = 0; j < 16; j++) x[j] = big_load32(source + 4 * j);
		for (j = 16; j < 64; j++) x[j] = sigma1(x[j - 2]) + x[j - 7] + sigma0(x[j - 15]) + x[j - 16];
		for (j = 0; j < 8; j++) h[j] = ctx->h[j];

		for (j = 0; j < 64; j++) {
			t1 = h[7] + Sigma1(h[4]) + Ch(h[4], h[5], h[6]) + K[j] + x[j];
			t2 = Sigma0(h[0]) + Maj(h[0], h[1], h[2]);

			h[7] = h[6]; h[6] = h[5]; h[5] = h[4];
			h[4] = h[3] + t1;
			h[3] = h[2]; h[2] = h[1]; h[1] = h[0];
			h[0] = t1 + t2;
		}

		for (j = 0; j < 8; j++) ctx->h[j] += h[j];
		len--;
		source += 64;
	}
}

/* interface */

void CYFER_SHA256_Init(SHA256_CTX *ctx)
{
	int i;
	ctx->buffer = malloc(2 * 64);
	for (i = 0; i < 8; i++) ctx->h[i] = iv[i];	
	ctx->length = 0; ctx->buflen = 0;
}

void CYFER_SHA256_Finish(SHA256_CTX *ctx, unsigned char *md)
{
	int i;
	sha256_compress_block(ctx, true);
	for (i = 0; i < 8; i++) big_store32(ctx->h[i], (md + 4 * i));
	free(ctx->buffer); ctx->buffer = NULL;
}

void CYFER_SHA256_Update(SHA256_CTX *ctx, const unsigned char *data, size_t len)
{
	while (len--) {
		ctx->buffer[ctx->buflen++] = *data++;
		if (ctx->buflen == 64) {
			sha256_compress_block(ctx, false);
			ctx->buflen = 0;
		}
	}
}

void CYFER_SHA256(const unsigned char *data, size_t len, unsigned char *md)
{
	SHA256_CTX ctx;

	CYFER_SHA256_Init(&ctx);
	CYFER_SHA256_Update(&ctx, data, len);
	CYFER_SHA256_Finish(&ctx, md);
}

