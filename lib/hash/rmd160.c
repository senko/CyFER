#include <stdlib.h>
#include <string.h>
#include <rmd160.h>


/* constants and transformations */

static const u32 iv1 = 0x67452301;
static const u32 iv2 = 0xefcdab89;
static const u32 iv3 = 0x98badcfe;
static const u32 iv4 = 0x10325476;
static const u32 iv5 = 0xc3d2e1f0;

#define f(u,v,w) (u ^ v ^ w)
#define g(u,v,w) ((u & v) | (~u & w))
#define h(u,v,w) ((u | ~v) ^ w)
#define k(u,v,w) ((u & w) | (v & ~w))
#define l(u,v,w) (u ^ (v | ~w))
#define rotl(t,s) ((t << s) | (t >> (32 - s)))

#define YL1 0x0
#define YL2 0x5a827999
#define YL3 0x6ed9eba1
#define YL4 0x8f1bbcdc
#define YL5 0xa953fd4e

#define YR1 0x50a28be6
#define YR2 0x5c4dd124
#define YR3 0x6d703ef3
#define YR4 0x7a6d76e9
#define YR5 0x0

static const u32 yl[80] = {
	YL1, YL1, YL1, YL1, YL1, YL1, YL1, YL1, YL1, YL1, YL1, YL1, YL1, YL1, YL1, YL1,
	YL2, YL2, YL2, YL2, YL2, YL2, YL2, YL2, YL2, YL2, YL2, YL2, YL2, YL2, YL2, YL2,
	YL3, YL3, YL3, YL3, YL3, YL3, YL3, YL3, YL3, YL3, YL3, YL3, YL3, YL3, YL3, YL3,
	YL4, YL4, YL4, YL4, YL4, YL4, YL4, YL4, YL4, YL4, YL4, YL4, YL4, YL4, YL4, YL4,
	YL5, YL5, YL5, YL5, YL5, YL5, YL5, YL5, YL5, YL5, YL5, YL5, YL5, YL5, YL5, YL5
};

static const int zl[80] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
	3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
	1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
	4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
};

static const int sl[80] = {
	11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
	7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
	11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
	11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
	9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
};

static const u32 yr[80] = {
	YR1, YR1, YR1, YR1, YR1, YR1, YR1, YR1, YR1, YR1, YR1, YR1, YR1, YR1, YR1, YR1,
	YR2, YR2, YR2, YR2, YR2, YR2, YR2, YR2, YR2, YR2, YR2, YR2, YR2, YR2, YR2, YR2,
	YR3, YR3, YR3, YR3, YR3, YR3, YR3, YR3, YR3, YR3, YR3, YR3, YR3, YR3, YR3, YR3,
	YR4, YR4, YR4, YR4, YR4, YR4, YR4, YR4, YR4, YR4, YR4, YR4, YR4, YR4, YR4, YR4,
	YR5, YR5, YR5, YR5, YR5, YR5, YR5, YR5, YR5, YR5, YR5, YR5, YR5, YR5, YR5, YR5
};

static const int zr[80] = {
	5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
	6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
	15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
	8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
	12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
};

static const int sr[80] = {
	8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
	9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
	9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
	15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
	8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
};

/* implementation */

static void rmd160_compress_block(RMD160_CTX *ctx, bool last)
{
	u32 x[16];
	u32 al, bl, cl, dl, el, ar, br, cr, dr, er, t;
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

		al = ctx->h1; bl = ctx->h2; cl = ctx->h3; dl = ctx->h4; el = ctx->h5;
		ar = ctx->h1; br = ctx->h2; cr = ctx->h3; dr = ctx->h4; er = ctx->h5;
		
		for (j = 0; j < 16; j++) {
			t = al + f(bl, cl, dl) + x[zl[j]] + yl[j];
			al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = al + rotl(t, sl[j]);
		}
		for (j = 16; j < 32; j++) {
			t = al + g(bl, cl, dl) + x[zl[j]] + yl[j];
			al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = al + rotl(t, sl[j]);
		}
		for (j = 32; j < 48; j++) {
			t = al + h(bl, cl, dl) + x[zl[j]] + yl[j];
			al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = al + rotl(t, sl[j]);
		}
		for (j = 48; j < 64; j++) {
			t = al + k(bl, cl, dl) + x[zl[j]] + yl[j];
			al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = al + rotl(t, sl[j]);
		}
		for (j = 64; j < 80; j++) {
			t = al + l(bl, cl, dl) + x[zl[j]] + yl[j];
			al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = al + rotl(t, sl[j]);
		}

		for (j = 0; j < 16; j++) {
			t = ar + l(br, cr, dr) + x[zr[j]] + yr[j];
			ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = ar + rotl(t, sr[j]);
		}
		for (j = 16; j < 32; j++) {
			t = ar + k(br, cr, dr) + x[zr[j]] + yr[j];
			ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = ar + rotl(t, sr[j]);
		}
		for (j = 32; j < 48; j++) {
			t = ar + h(br, cr, dr) + x[zr[j]] + yr[j];
			ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = ar + rotl(t, sr[j]);
		}
		for (j = 48; j < 64; j++) {
			t = ar + g(br, cr, dr) + x[zr[j]] + yr[j];
			ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = ar + rotl(t, sr[j]);
		}
		for (j = 64; j < 80; j++) {
			t = ar + f(br, cr, dr) + x[zr[j]] + yr[j];
			ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = ar + rotl(t, sr[j]);
		}
		t = ctx->h1; ctx->h1 = ctx->h2 + cl + dr; ctx->h2 = ctx->h3 + dl + er;
		ctx->h3 = ctx->h4 + el + ar; ctx->h4 = ctx->h5 + al + br; ctx->h5 = t + bl + cr;
		len--;
		source += 64;
	}
}

/* interface */

void CYFER_RMD160_Init(RMD160_CTX *ctx)
{
	ctx->buffer = malloc(2 * 64);
	ctx->h1 = iv1; ctx->h2 = iv2; ctx->h3 = iv3; ctx->h4 = iv4; ctx->h5 = iv5;
	ctx->length = 0; ctx->buflen = 0;
}

void CYFER_RMD160_Finish(RMD160_CTX *ctx, unsigned char *md)
{
	rmd160_compress_block(ctx, true);
	little_store32(ctx->h1, md);
	little_store32(ctx->h2, md + 4);
	little_store32(ctx->h3, md + 8);
	little_store32(ctx->h4, md + 12);
	little_store32(ctx->h5, md + 16);
	free(ctx->buffer); ctx->buffer = NULL;
}

void CYFER_RMD160_Update(RMD160_CTX *ctx, const unsigned char *data, size_t len)
{
	while (len--) {
		ctx->buffer[ctx->buflen++] = *data++;
		if (ctx->buflen == 64) {
			rmd160_compress_block(ctx, false);
			ctx->buflen = 0;
		}
	}
}

void CYFER_RMD160(const unsigned char *data, size_t len, unsigned char *md)
{
	RMD160_CTX ctx;

	CYFER_RMD160_Init(&ctx);
	CYFER_RMD160_Update(&ctx, data, len);
	CYFER_RMD160_Finish(&ctx, md);
}

