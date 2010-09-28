#include <stdlib.h>
#include <string.h>
#include <deal.h>


/* constants */

static const u8 deskey[8] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
};

/* implementation */
static void key_schedule(DEAL_CTX *ctx, DES_CTX *des, const unsigned char *key)
{
	int i;
	u8 k[6][8];
	u8 tmp[8];

	CYFER_DES_Encrypt(des, key, k[0]);

	for (i = 0; i < 8; i++) tmp[i] = key[8 + i] ^ k[0][i];
	CYFER_DES_Encrypt(des, tmp, k[1]);

	for (i = 0; i < 8; i++) tmp[i] = key[i] ^ k[1][i]; tmp[0] ^= 0x80;
	CYFER_DES_Encrypt(des, tmp, k[2]);

	for (i = 0; i < 8; i++) tmp[i] = key[8 + i] ^ k[2][i]; tmp[0] ^= 0x40;
	CYFER_DES_Encrypt(des, tmp, k[3]);

	for (i = 0; i < 8; i++) tmp[i] = key[i] ^ k[3][i]; tmp[0] ^= 0x20;
	CYFER_DES_Encrypt(des, tmp, k[4]);

	for (i = 0; i < 8; i++) tmp[i] = key[8 + i] ^ k[4][i]; tmp[0] ^= 0x10;
	CYFER_DES_Encrypt(des, tmp, k[5]);

	for (i = 0; i < 6; i++) CYFER_DES_Init(&(ctx->des[i]), k[i]);
}

/* interface */

void CYFER_DEAL_Init(DEAL_CTX *ctx, const unsigned char *key)
{
	DES_CTX des;

	CYFER_DES_Init(&des, deskey);
	key_schedule(ctx, &des, key);
	CYFER_DES_Finish(&des);
}

void CYFER_DEAL_Finish(DEAL_CTX *ctx)
{
	int i;
	for (i = 0; i < 6; i++) CYFER_DES_Finish(&(ctx->des[i]));
}

void CYFER_DEAL_Encrypt(DEAL_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	unsigned char L[8], R[8], tmp[8];
	int r, i;

	memcpy(L, input, 8); memcpy(R, input + 8, 8);
	for (r = 0; r < 6; r++) {
		CYFER_DES_Encrypt(&(ctx->des[r]), L, tmp);
		for (i = 0; i < 8; i++) tmp[i] ^= R[i];
		memcpy(R, L, 8); memcpy(L, tmp, 8);
	}
	memcpy(output, L, 8); memcpy(output + 8, R, 8);
}

void CYFER_DEAL_Decrypt(DEAL_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	unsigned char L[8], R[8], tmp[8];
	int r, i;

	memcpy(L, input + 8, 8); memcpy(R, input, 8);
	for (r = 5; r >= 0; r--) {
		CYFER_DES_Encrypt(&(ctx->des[r]), L, tmp);
		for (i = 0; i < 8; i++) tmp[i] ^= R[i];
		memcpy(R, L, 8); memcpy(L, tmp, 8);
	}
	memcpy(output + 8, L, 8); memcpy(output, R, 8);
}

