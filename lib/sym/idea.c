#include <stdlib.h>
#include <string.h>
#include <idea.h>


/* constants and transformations */

#define rotl(s,t) (((s) << (t)) | ((s) >> (8 - (t))))
#define rotr(s,t) (((s) >> (t)) | ((s) << (8 - (t))))
#define big_load16(x) (((u16) (x)[1]) + ((u16) (x)[0]) * 256)
#define big_store16(v,x) { (x)[1] = (u8) (v & 255); (x)[0] = (u8) ((v >> 8) & 255); }

/* implementation */

#define xor(a, b) ((a) ^ (b))
#define add(a, b) (((a) + (b)) & 0xffff)
#define minus(a) ((0 - (a)) & 0xffff)

static inline u16 mul(u16 a, u16 b)
{
	u32 p = ((u32) a) * ((u32) b);
	if (p) {
		b = p & 65535; a = p >> 16;
		return (((b - a) + (b < a)) & 65535);
	}
	if (a) return ((1 - a) & 65535);
	return ((1 - b) & 65535);
}

static inline u16 inv(u16 x)
{
	long a = (long) x, c = 0x10001, d, e = 0, f = 1, g;
	while (a > 0) {
		d = c % a; g = e - c / a * f; c = a; a = d; e = f; f = g;
	}
	if (e < 0) e++;
	return (u16) (e & 0xffff);
}

static inline void rotl25(u8 *key)
{
	int i;
	u8 carry[3], tmp;

	/* rotate left by 24 bits */
	memcpy(carry, key, 3);
	for (i = 0; i < 13; i++) key[i] = key[i + 3];
	for (i = 0; i < 3; i++) key[13 + i] = carry[i];

	/* rotate by 1 bit */
	carry[0] = (key[0] & 128) >> 7;
	for (i = 15; i >= 0; i--) {
		key[i] = rotl(key[i], 1);
		tmp = key[i] & 1;
		key[i] = (key[i] & ~1) + carry[0];
		carry[0] = tmp;
	}
}

static void key_schedule(IDEA_CTX *ctx, const unsigned char *key)
{
	int i, j;
	unsigned char tmp[16];

	memcpy(tmp, key, 16);
	for (j = 0; j < 6; j++) {
		for (i = 0; i < 8; i++) ctx->K[8 * j + i] = big_load16(tmp + 2 * i);
		rotl25(tmp);
	}
	for (i = 0; i < 4; i++) ctx->K[48 + i] = big_load16(tmp + 2 * i);
}

static void key_schedule_inv(IDEA_CTX *ctx)
{
	int r;

	ctx->Kinv[0] = inv(ctx->K[48]); ctx->Kinv[1] = minus(ctx->K[49]); ctx->Kinv[2] = minus(ctx->K[50]);
	ctx->Kinv[3] = inv(ctx->K[51]); ctx->Kinv[4] = ctx->K[46]; ctx->Kinv[5] = ctx->K[47];

	for (r = 1; r < 8; r++) {
		ctx->Kinv[6 * r] = inv(ctx->K[6 * (10 - r - 2)]);
		ctx->Kinv[6 * r + 1] = minus(ctx->K[6 * (10 - r - 2) + 2]);
		ctx->Kinv[6 * r + 2] = minus(ctx->K[6 * (10 - r - 2) + 1]);
		ctx->Kinv[6 * r + 3] = inv(ctx->K[6 * (10 - r - 2) + 3]);
		ctx->Kinv[6 * r + 4] = ctx->K[6 * (9 - r - 2) + 4];
		ctx->Kinv[6 * r + 5] = ctx->K[6 * (9 - r - 2) + 5];
	}
	ctx->Kinv[48] = inv(ctx->K[0]); ctx->Kinv[49] = minus(ctx->K[1]);
	ctx->Kinv[50] = minus(ctx->K[2]); ctx->Kinv[51] = inv(ctx->K[3]);
}

static void idea_encrypt_block(u16 *X, u16 *K)
{
	int i;
	u16 t0, t1, t2, a;

	for (i = 0; i < 8; i++) {
		X[0] = mul(X[0], K[6 * i]); X[3] = mul(X[3], K[6 * i + 3]);
		X[1] = add(X[1], K[6 * i + 1]); X[2] = add(X[2], K[6 * i + 2]);
		t0 = mul(K[6 * i + 4], xor(X[0], X[2]));
		t1 = mul(K[6 * i + 5], add(t0, xor(X[1], X[3])));
		t2 = add(t0, t1);
		X[0] = xor(X[0], t1); X[3] = xor(X[3], t2);
		a = xor(X[1], t2); X[1] = xor(X[2], t1); X[2] = a;
	}
	t0 = add(X[1], K[50]);
	X[0] = mul(X[0], K[48]); X[3] = mul(X[3], K[51]);
	X[1] = add(X[2], K[49]); X[2] = t0;
}

/* interface */

void CYFER_IDEA_Init(IDEA_CTX *ctx, const unsigned char *key)
{
	key_schedule(ctx, key);
	key_schedule_inv(ctx);
}

void CYFER_IDEA_Finish(IDEA_CTX *ctx)
{
	ctx = NULL; /* suppress warning */
}

void CYFER_IDEA_Encrypt(IDEA_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	u16 tmp[4];
	int i;

	for (i = 0; i < 4; i++) tmp[i] = big_load16(input + 2 * i);
	idea_encrypt_block(tmp, ctx->K);
	for (i = 0; i < 4; i++) big_store16(tmp[i], output + 2 * i);
}

void CYFER_IDEA_Decrypt(IDEA_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	u16 tmp[4];
	int i;

	for (i = 0; i < 4; i++) tmp[i] = big_load16(input + 2 * i);
	idea_encrypt_block(tmp, ctx->Kinv);
	for (i = 0; i < 4; i++) big_store16(tmp[i], output + 2 * i);
}


