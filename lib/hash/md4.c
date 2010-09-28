#include <stdlib.h>
#include <string.h>
#include <md4.h>


/* constants and transformations */

static const u32 iv1 = 0x67452301UL;
static const u32 iv2 = 0xefcdab89UL;
static const u32 iv3 = 0x98badcfeUL;
static const u32 iv4 = 0x10325476UL;

#define Y0 0UL
#define Y1 0x5a827999UL
#define Y2 0x6ed9eba1UL

#define	f(u,v,w) ((u & v) | (~u & w))
#define	g(u,v,w) ((u & v) | (u & w) | (v & w))
#define	h(u,v,w) ((u ^ v) ^ w)
#define rotl(t,s) ((t << s) | (t >> (32 - s)))

static const u32 y[48] = {
	Y0, Y0, Y0, Y0, Y0, Y0, Y0, Y0, Y0, Y0, Y0, Y0, Y0, Y0, Y0, Y0,
	Y1, Y1, Y1, Y1, Y1, Y1, Y1, Y1, Y1, Y1, Y1, Y1, Y1, Y1, Y1, Y1,
	Y2, Y2, Y2, Y2, Y2, Y2, Y2, Y2, Y2, Y2, Y2, Y2, Y2, Y2, Y2, Y2
};

static const int z[48] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15,
	0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15
};

static const int s[48] = {
	3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19,
	3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13,
	3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15
};

/* implementation */

static void md4_compress_block(MD4_CTX *ctx, bool last)
{
	u32 x[16];
	u32 a, b, c, d, t;
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

		little_store32((u32) ctx->length, source + len); len += 4;
		little_store32((u32) (ctx->length >> 32), source + len); len += 4;
	}
	len /= 64;

	while (len) {
		for (j = 0; j < 16; j++) x[j] = little_load32(source + 4 * j);
		a = ctx->h1; b = ctx->h2; c = ctx->h3; d = ctx->h4;
		for (j = 0; j < 16; j++) {
			t = a + f(b, c, d) + x[z[j]] + y[j];
			a = d; d = c; c = b; b = rotl(t, s[j]);
		}
		for (j = 16; j < 32; j++) {
			t = a + g(b, c, d) + x[z[j]] + y[j];
			a = d; d = c; c = b; b = rotl(t, s[j]);
		}
		for (j = 32; j < 48; j++) {
			t = a + h(b, c, d) + x[z[j]] + y[j];
			a = d; d = c; c = b; b = rotl(t, s[j]);
		}
		ctx->h1 += a; ctx->h2 += b; ctx->h3 += c; ctx->h4 += d;
		len--;
		source += 64;
	}
}

/* interface */

void CYFER_MD4_Init(MD4_CTX *ctx)
{
	ctx->buffer = malloc(2 * 64);
	ctx->h1 = iv1; ctx->h2 = iv2; ctx->h3 = iv3; ctx->h4 = iv4;
	ctx->length = 0; ctx->buflen = 0;
}

void CYFER_MD4_Finish(MD4_CTX *ctx, unsigned char *md)
{
	md4_compress_block(ctx, true);
	little_store32(ctx->h1, md);
	little_store32(ctx->h2, md + 4);
	little_store32(ctx->h3, md + 8);
	little_store32(ctx->h4, md + 12);
	free(ctx->buffer); ctx->buffer = NULL;
}

void CYFER_MD4_Update(MD4_CTX *ctx, const unsigned char *data, size_t len)
{
	while (len--) {
		ctx->buffer[ctx->buflen++] = *data++;
		if (ctx->buflen == 64) {
			md4_compress_block(ctx, false);
			ctx->buflen = 0;
		}
	}
}

void CYFER_MD4(const unsigned char *data, size_t len, unsigned char *md)
{
	MD4_CTX ctx;

	CYFER_MD4_Init(&ctx);
	CYFER_MD4_Update(&ctx, data, len);
	CYFER_MD4_Finish(&ctx, md);
}

