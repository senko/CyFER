#include <stdlib.h>
#include <string.h>
#include <threeway.h>


/* constants and transformations */

#define START_ENC 0x0b0b
#define START_DEC 0xb1b1

#define rotl(s, t) (((s) << (t)) | ((s) >> (32 - (t))))
#define rotr(s, t) (((s) >> (t)) | ((s) << (32 - (t))))

#define pi_1(x) { x[0] = rotr(x[0], 10); x[2] = rotl(x[2], 1); }
#define pi_2(x) { x[2] = rotr(x[2], 10); x[0] = rotl(x[0], 1); }

static const u32 encval[12] = {
	0xb0b, 0x1616, 0x2c2c, 0x5858, 0xb0b0, 0x7171, 0xe2e2, 0xd5d5, 0xbbbb, 0x6767, 0xcece, 0x8d8d
};

static const u32 decval[12] = {
	0xb1b1, 0x7373, 0xe6e6, 0xdddd, 0xabab, 0x4747, 0x8e8e, 0xd0d, 0x1a1a, 0x3434, 0x6868, 0xd0d0
};

/* implementation */

static inline u32 mu32(u32 val)
{
	int i;
	u32 ret = 0;

	for (i = 0; i < 31; i++) {
		ret ^= val & 1; ret <<= 1; val >>= 1;
	}
	ret ^= val & 1;
	return ret;
}

static inline void mu(u32 *x)
{
	u32 tmp;

	x[1] = mu32(x[1]);
	tmp = mu32(x[0]);
	x[0] = mu32(x[2]);
	x[2] = tmp;
}

static inline void gamma(u32 *x)
{
	u32 tmp[3];

	tmp[0] = x[0] ^ (x[1] | ~x[2]);
	tmp[1] = x[1] ^ (x[2] | ~x[0]);
	tmp[2] = x[2] ^ (x[0] | ~x[1]);
	x[0] = tmp[0]; x[1] = tmp[1]; x[2] = tmp[2];
}

static inline void theta(u32 *x)
{
	u32 tmp[3];
	int i;

	for (i = 0; i < 3; i++) {
		tmp[i] = x[i] ^ (x[i] >> 16) ^ (x[(i + 1) % 3] << 16) ^ (x[(i + 1) % 3] >> 16) ^
			(x[(i + 2) % 3] << 16) ^ (x[(i + 1) % 3] >> 24) ^ (x[(i + 2) % 3] << 8) ^
			(x[(i + 2) % 3] >> 8) ^ (x[i] << 24) ^ (x[(i + 2) % 3] >> 16) ^ (x[i] << 16) ^
			(x[(i + 2) % 3] >> 24) ^ (x[i] << 8);
	}
	x[0] = tmp[0]; x[1] = tmp[1]; x[2] = tmp[2];
}

static inline void rho(u32 *x)
{
	theta(x);
	pi_1(x);
	gamma(x);
	pi_2(x);
}

static void key_schedule(THREEWAY_CTX *ctx, const unsigned char *key)
{
	ctx->key[0] = ctx->ikey[0] = big_load32(key);
	ctx->key[1] = ctx->ikey[1] = big_load32(key + 4);
	ctx->key[2] = ctx->ikey[2] = big_load32(key + 8);
	theta(ctx->ikey);
	mu(ctx->ikey);
}

static void encrypt_block(THREEWAY_CTX *ctx, u32 *x)
{
	int i;

	for (i = 0; i < 11; i++) {
		x[0] ^= ctx->key[0] ^ (encval[i] << 16);
		x[1] ^= ctx->key[1];
		x[2] ^= ctx->key[2] ^ encval[i];
		rho(x);
	}
	x[0] ^= ctx->key[0] ^ (encval[i] << 16);
	x[1] ^= ctx->key[1];
	x[2] ^= ctx->key[2] ^ encval[i];
	theta(x);
}

static void decrypt_block(THREEWAY_CTX *ctx, u32 *x)
{
	int i;

	mu(x);
	for (i = 0; i < 11; i++) {
		x[0] ^= ctx->ikey[0] ^ (decval[i] << 16);
		x[1] ^= ctx->ikey[1];
		x[2] ^= ctx->ikey[2] ^ decval[i];
		rho(x);
	}
	x[0] ^= ctx->ikey[0] ^ (decval[i] << 16);
	x[1] ^= ctx->ikey[1];
	x[2] ^= ctx->ikey[2] ^ decval[i];
	theta(x);
	mu(x);
}


/* interface */

void CYFER_THREEWAY_Init(THREEWAY_CTX *ctx, const unsigned char *key)
{
	key_schedule(ctx, key);
}

void CYFER_THREEWAY_Finish(THREEWAY_CTX *ctx)
{
	ctx = NULL; /* suppress warning */
}

void CYFER_THREEWAY_Encrypt(THREEWAY_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	u32 tmp[3];

	tmp[0] = big_load32(input); tmp[1] = big_load32(input + 4); tmp[2] = big_load32(input + 8);
	encrypt_block(ctx, tmp);
	big_store32(tmp[0], output); big_store32(tmp[1], output + 4); big_store32(tmp[2], output + 8);
}

void CYFER_THREEWAY_Decrypt(THREEWAY_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	u32 tmp[3];

	tmp[0] = big_load32(input); tmp[1] = big_load32(input + 4); tmp[2] = big_load32(input + 8);
	decrypt_block(ctx, tmp);
	big_store32(tmp[0], output); big_store32(tmp[1], output + 4); big_store32(tmp[2], output + 8);
}

