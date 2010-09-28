#include <stdlib.h>
#include <string.h>
#include <rc5.h>


/* constants and transformations */
/* Note: We implement RC5-32/12/16 */

#define P32 0xb7e15163UL;
#define Q32 0x9e3779b9UL;

#define rotl(s, t) (((s) << (t)) | ((s) >> (32 - (t))))
#define rotr(s, t) (((s) >> (t)) | ((s) << (32 - (t))))

/* implementation */

static void key_schedule(RC5_CTX *ctx, const unsigned char *key)
{
	u32 L[4], A, B;
	int i, j, k;

	for (i = 0; i < 4; i++) L[i] = little_load32((unsigned char *) key + 4 * i);

	ctx->S[0] = P32;
	for (i = 1; i < 26; i++) ctx->S[i] = ctx->S[i - 1] + Q32;

	i = j = 0; A = B = 0;
	for (k = 0; k < (3 * 26); k++) {
		A = ctx->S[i] = rotl(ctx->S[i] + A + B, 3);
		B = L[j] = rotl(L[j] + A + B, A + B);
		i = (i + 1) % 26;
		j = (j + 1) % 4;
	}
}

static void rc5_encrypt_block(RC5_CTX *ctx, u8 *block)
{
	int i;
	u32 A, B;

	A = little_load32(block) + ctx->S[0]; B = little_load32(block + 4) + ctx->S[1];
	for (i = 1; i <= 12; i++) {
		A = rotl((A ^ B), B) + ctx->S[2 * i];
		B = rotl((B ^ A), A) + ctx->S[2 * i + 1];
	}
	little_store32(A, block); little_store32(B, block + 4);
}

static void rc5_decrypt_block(RC5_CTX *ctx, u8 *block)
{
	int i;
	u32 A, B;

	A = little_load32(block); B = little_load32(block + 4);
	for (i = 12; i >= 1; i--) {
		B = rotr(B - ctx->S[2 * i + 1], A) ^ A;
		A = rotr(A - ctx->S[2 * i], B) ^ B;
	}
	B -= ctx->S[1]; A -= ctx->S[0];
	little_store32(A, block); little_store32(B, block + 4);
}

/* interface */

void CYFER_RC5_Init(RC5_CTX *ctx, const unsigned char *key)
{
	key_schedule(ctx, key);
}

void CYFER_RC5_Finish(RC5_CTX *ctx)
{
	ctx = NULL; /* suppress warning */
}

void CYFER_RC5_Encrypt(RC5_CTX *ctx, const unsigned char *input, unsigned char *output)
{

	memcpy(output, input, 8);
	rc5_encrypt_block(ctx, output);
}

void CYFER_RC5_Decrypt(RC5_CTX *ctx, const unsigned char *input, unsigned char *output)
{

	memcpy(output, input, 8);
	rc5_decrypt_block(ctx, output);
}

