#include <stdlib.h>
#include <string.h>
#include <rc4.h>

/* implementation */

#define swap(a, b) { u8 t = a; a = b; b = t; }

static void key_schedule(RC4_CTX *ctx, const unsigned char *key, size_t keylen)
{
	int i, f;

	for (i = 0; i < 256; i++) ctx->state[i] = (u8) i;

	f = 0;
	for (i = 0; i < 256; i++) {
		f = (f + ctx->state[i] + key[i % keylen]) % 256;
		swap(ctx->state[f], ctx->state[i]);	
	}
	ctx->i = 0; ctx->f = 0;
}

static void rc4_encrypt(RC4_CTX *ctx, unsigned char *data, size_t len)
{
	u8 t;

	while (len--) {
		ctx->i = (ctx->i + 1) % 256;
		ctx->f = (ctx->f + ctx->state[ctx->i]) % 256;
		swap(ctx->state[ctx->i], ctx->state[ctx->f]);
		t = (ctx->state[ctx->i] + ctx->state[ctx->f]) % 256;

		*data = *data ^ ctx->state[t];
		data++;
	}
}

/* interface */

void CYFER_RC4_Init(RC4_CTX *ctx, const unsigned char *key, size_t keylen)
{
	key_schedule(ctx, key, keylen);
}

void CYFER_RC4_Finish(RC4_CTX *ctx)
{
	ctx = NULL; /* suppress warning */
}

void CYFER_RC4_Encrypt(RC4_CTX *ctx, const unsigned char *input, unsigned char *output, size_t len)
{
	memcpy(output, input, len);
	rc4_encrypt(ctx, output, len);
}

void CYFER_RC4_Decrypt(RC4_CTX *ctx, const unsigned char *input, unsigned char *output, size_t len)
{
	CYFER_RC4_Encrypt(ctx, input, output, len);
}

