#include <stdlib.h>
#include <string.h>
#include <sha1.h>


/* constants and transformations */

static const u32 iv1 = 0x67452301;
static const u32 iv2 = 0xefcdab89;
static const u32 iv3 = 0x98badcfe;
static const u32 iv4 = 0x10325476;
static const u32 iv5 = 0xc3d2e1f0;

static const u32 y1 = 0x5a827999;
static const u32 y2 = 0x6ed9eba1;
static const u32 y3 = 0x8f1bbcdc;
static const u32 y4 = 0xca62c1d6;

#define	f(u,v,w) ((u & v) | (~u & w))
#define	g(u,v,w) ((u & v) | (u & w) | (v & w))
#define	h(u,v,w) ((u ^ v) ^ w)
#define rotl(t,s) (((t) << s) | ((t) >> (32 - s)))

/* implementation */

static void sha1_compress_block(SHA1_CTX *ctx, bool last)
{
	u32 x[80];
	u32 a, b, c, d, e, t;
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
		for (j = 16; j < 80; j++) x[j] = rotl(x[j - 3] ^ x[j - 8] ^ x[j - 14] ^ x[j - 16], 1);

		a = ctx->h1; b = ctx->h2; c = ctx->h3; d = ctx->h4; e = ctx->h5;
		for (j = 0; j < 20; j++) {
			t = rotl(a, 5) + f(b, c, d) + e + x[j] + y1;
			e = d; d = c; c = rotl(b, 30); b = a; a = t;
		}
		for (j = 20; j < 40; j++) {
			t = rotl(a, 5) + h(b, c, d) + e + x[j] + y2;
			e = d; d = c; c = rotl(b, 30); b = a; a = t;
		}
		for (j = 40; j < 60; j++) {
			t = rotl(a, 5) + g(b, c, d) + e + x[j] + y3;
			e = d; d = c; c = rotl(b, 30); b = a; a = t;
		}
		for (j = 60; j < 80; j++) {
			t = rotl(a, 5) + h(b, c, d) + e + x[j] + y4;
			e = d; d = c; c = rotl(b, 30); b = a; a = t;
		}
		ctx->h1 += a; ctx->h2 += b; ctx->h3 += c; ctx->h4 += d; ctx->h5 += e;
		len--;
		source += 64;
	}
}

/* interface */

void CYFER_SHA1_Init(SHA1_CTX *ctx)
{
	ctx->buffer = malloc(2 * 64);
	ctx->h1 = iv1; ctx->h2 = iv2; ctx->h3 = iv3; ctx->h4 = iv4; ctx->h5 = iv5;
	ctx->length = 0; ctx->buflen = 0;
}

void CYFER_SHA1_Finish(SHA1_CTX *ctx, unsigned char *md)
{
	sha1_compress_block(ctx, true);
	big_store32(ctx->h1, md);
	big_store32(ctx->h2, md + 4);
	big_store32(ctx->h3, md + 8);
	big_store32(ctx->h4, md + 12);
	big_store32(ctx->h5, md + 16);
	free(ctx->buffer); ctx->buffer = NULL;
}

void CYFER_SHA1_Update(SHA1_CTX *ctx, const unsigned char *data, size_t len)
{
	while (len--) {
		ctx->buffer[ctx->buflen++] = *data++;
		if (ctx->buflen == 64) {
			sha1_compress_block(ctx, false);
			ctx->buflen = 0;
		}
	}
}

void CYFER_SHA1(const unsigned char *data, size_t len, unsigned char *md)
{
	SHA1_CTX ctx;

	CYFER_SHA1_Init(&ctx);
	CYFER_SHA1_Update(&ctx, data, len);
	CYFER_SHA1_Finish(&ctx, md);
}

