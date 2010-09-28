#include <stdlib.h>
#include <string.h>
#include <rc6.h>


/* constants and transformations */
/* Note: We implement RC6-32/20/16 (AES-specification compatible) */

#define P32 0xb7e15163UL;
#define Q32 0x9e3779b9UL;

#define rotl(s, t) (((s) << (t)) | ((s) >> (32 - (t))))
#define rotr(s, t) (((s) >> (t)) | ((s) << (32 - (t))))

#define data_load() { \
	A = little_load32(block); B = little_load32(block + 4); \
	C = little_load32(block + 8); D = little_load32(block + 12); \
}
#define data_store() { \
	little_store32(A, block); little_store32(B, block + 4); \
	little_store32(C, block + 8); little_store32(D, block + 12); \
}

/* implementation */

static void key_schedule(RC6_CTX *ctx, const unsigned char *key)
{
	u32 L[4], A, B;
	int i, j, k;

	for (i = 0; i < 4; i++) L[i] = little_load32((unsigned char *) key + 4 * i);

	ctx->S[0] = P32;
	for (i = 1; i < 44; i++) ctx->S[i] = ctx->S[i - 1] + Q32;

	i = j = 0; A = B = 0;
	for (k = 0; k < (3 * 44); k++) {
		A = ctx->S[i] = rotl(ctx->S[i] + A + B, 3);
		B = L[j] = rotl(L[j] + A + B, A + B);
		i = (i + 1) % 44;
		j = (j + 1) % 4;
	}
}

static void rc6_encrypt_block(RC6_CTX *ctx, u8 *block)
{
	int i;
	u32 A, B, C, D, t, u;

	data_load();
	B += ctx->S[0]; D += ctx->S[1];
	
	for (i = 1; i <= 20; i++) {
		t = rotl(B * (2 * B + 1), 5);
		u = rotl(D * (2 * D + 1), 5);
		A = rotl(A ^ t, u) + ctx->S[2 * i];
		C = rotl(C ^ u, t) + ctx->S[2 * i + 1];
		t = A; A = B; B = C; C = D; D = t;
	} 
	A += ctx->S[42]; C += ctx->S[43];
	data_store();
}

static void rc6_decrypt_block(RC6_CTX *ctx, u8 *block)
{
	int i;
	u32 A, B, C, D, t, u;

	data_load();
	C -= ctx->S[43]; A -= ctx->S[42];

	for (i = 20; i >= 1; i--) {
		t = D; D = C; C = B; B = A; A = t;
		u = rotl(D * (2 * D + 1), 5);
		t = rotl(B * (2 * B + 1), 5);
		C = rotr(C - ctx->S[2 * i + 1], t) ^ u;
		A = rotr(A - ctx->S[2 * i], u) ^ t;
	} 
	D -= ctx->S[1]; B -= ctx->S[0];
	data_store();
}

/* interface */

void CYFER_RC6_Init(RC6_CTX *ctx, const unsigned char *key)
{
	key_schedule(ctx, key);
}

void CYFER_RC6_Finish(RC6_CTX *ctx)
{
	ctx = NULL; /* suppress warning */
}

void CYFER_RC6_Encrypt(RC6_CTX *ctx, const unsigned char *input, unsigned char *output)
{

	memcpy(output, input, 16);
	rc6_encrypt_block(ctx, output);
}

void CYFER_RC6_Decrypt(RC6_CTX *ctx, const unsigned char *input, unsigned char *output)
{

	memcpy(output, input, 16);
	rc6_decrypt_block(ctx, output);
}

