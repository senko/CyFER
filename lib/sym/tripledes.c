#include <stdlib.h>
#include <string.h>
#include <tripledes.h>

/* interface */

/* NOTE: We implement outer (the feedback is done once for TripleDES operation) EDE TripleDES */
void CYFER_TRIPLEDES_Init(TRIPLEDES_CTX *ctx, const unsigned char *key)
{
	CYFER_DES_Init(&ctx->a, key);
	CYFER_DES_Init(&ctx->b, key + 8);
	CYFER_DES_Init(&ctx->c, key + 16);
}

void CYFER_TRIPLEDES_Finish(TRIPLEDES_CTX *ctx)
{
	CYFER_DES_Finish(&(ctx->a));
	CYFER_DES_Finish(&(ctx->b));
	CYFER_DES_Finish(&(ctx->c));
}

void CYFER_TRIPLEDES_Encrypt(TRIPLEDES_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	unsigned char tmp1[8], tmp2[8];

	CYFER_DES_Encrypt(&(ctx->a), input, tmp1);
	CYFER_DES_Decrypt(&(ctx->b), tmp1, tmp2);
	CYFER_DES_Encrypt(&(ctx->c), tmp2, output);
}

void CYFER_TRIPLEDES_Decrypt(TRIPLEDES_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	unsigned char tmp1[8], tmp2[8];

	CYFER_DES_Decrypt(&(ctx->c), input, tmp1);
	CYFER_DES_Encrypt(&(ctx->b), tmp1, tmp2);
	CYFER_DES_Decrypt(&(ctx->a), tmp2, output);
}

