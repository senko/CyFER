#include <string.h>
#include <util.h>
#include <cyfer/cipher.h>
#include <modes.h>

static CYFER_BlockCipher_t CYFER_BlockCiphers[] = {
	/* type, name, keylen, min_keylen, blocklen */
	{ CYFER_CIPHER_BLOWFISH, "Blowfish", 56, 4, 8 },
	{ CYFER_CIPHER_DES, "DES", 8, 8, 8 },
	{ CYFER_CIPHER_DESX, "DESX", 24, 24, 8 },
	{ CYFER_CIPHER_TRIPLEDES, "TripleDES", 24, 24, 8 },
	{ CYFER_CIPHER_RC2, "RC2", 128, 1, 8 },
	{ CYFER_CIPHER_RC5, "RC5", 16, 16, 8 },
	{ CYFER_CIPHER_RC6, "RC6", 16, 16, 16 },
	{ CYFER_CIPHER_IDEA, "IDEA", 16, 16, 8 },
	{ CYFER_CIPHER_AES, "AES", 16, 16, 16 },
	{ CYFER_CIPHER_DEAL, "DEAL", 16, 16, 16 },
	{ CYFER_CIPHER_THREEWAY, "3-Way", 12, 12, 12 },
	{ CYFER_CIPHER_NONE, NULL, 0, 0, 0 }
};

static CYFER_StreamCipher_t CYFER_StreamCiphers[] = {
	{ CYFER_CIPHER_RC4, "RC4", 16, 5 },
	{ CYFER_CIPHER_NONE, NULL, 0, 0 }
};

CYFER_API CYFER_BlockCipher_t *CYFER_BlockCipher_Get_Supported(void)
{
	return CYFER_BlockCiphers;
}

CYFER_API int CYFER_BlockCipher_Select(const char *name, size_t *keylen, size_t *minkey, size_t *length)
{
	int i;
	for (i = 0; CYFER_BlockCiphers[i].type != CYFER_CIPHER_NONE; i++)
		if (!strcmp(name, CYFER_BlockCiphers[i].name)) break;
	if (keylen) *keylen = CYFER_BlockCiphers[i].keylen;
	if (length) *length = CYFER_BlockCiphers[i].length;
	if (minkey) *minkey = CYFER_BlockCiphers[i].minkey;
	return CYFER_BlockCiphers[i].type;
}


CYFER_API CYFER_BLOCK_CIPHER_CTX *CYFER_BlockCipher_Init(int type, const unsigned char *key, size_t keylen, int mode, const unsigned char *ivec)
{
	CYFER_BLOCK_CIPHER_CTX *ctx;
	size_t len;
	int idx;
	void *encrypt, *decrypt, *cctx;

	for (idx = 0; CYFER_BlockCiphers[idx].type != CYFER_CIPHER_NONE; idx++)
		if (type == CYFER_BlockCiphers[idx].type) break;
	if (CYFER_BlockCiphers[idx].type == CYFER_CIPHER_NONE) return NULL;

	if ((keylen < CYFER_BlockCiphers[idx].minkey) || (keylen > CYFER_BlockCiphers[idx].keylen)) return NULL;
	len = CYFER_BlockCiphers[idx].length;
	
	ctx = malloc(sizeof(CYFER_BLOCK_CIPHER_CTX));
	if (!ctx) return NULL;

	if (mode == CYFER_MODE_NONE) mode = CYFER_MODE_ECB;

	ctx->type = type;
	switch (type) {
		case CYFER_CIPHER_BLOWFISH:
			CYFER_BLOWFISH_Init(&ctx->u.blowfish, key, keylen);
			encrypt = CYFER_BLOWFISH_Encrypt; decrypt = CYFER_BLOWFISH_Decrypt; cctx = &ctx->u.blowfish;
			break;
		case CYFER_CIPHER_DES:
			CYFER_DES_Init(&ctx->u.des, key);
			encrypt = CYFER_DES_Encrypt; decrypt = CYFER_DES_Decrypt; cctx = &ctx->u.des;
			break;
		case CYFER_CIPHER_DESX:
			CYFER_DESX_Init(&ctx->u.desx, key);
			encrypt = CYFER_DESX_Encrypt; decrypt = CYFER_DESX_Decrypt; cctx = &ctx->u.desx;
			break;
		case CYFER_CIPHER_TRIPLEDES:
			CYFER_TRIPLEDES_Init(&ctx->u.tripledes, key);
			encrypt = CYFER_TRIPLEDES_Encrypt; decrypt = CYFER_TRIPLEDES_Decrypt; cctx = &ctx->u.tripledes;
			break;
		case CYFER_CIPHER_RC2:
			CYFER_RC2_Init(&ctx->u.rc2, key, keylen);
			encrypt = CYFER_RC2_Encrypt; decrypt = CYFER_RC2_Decrypt; cctx = &ctx->u.rc2;
			break;
		case CYFER_CIPHER_RC5:
			CYFER_RC5_Init(&ctx->u.rc5, key);
			encrypt = CYFER_RC5_Encrypt; decrypt = CYFER_RC5_Decrypt; cctx = &ctx->u.rc5;
			break;
		case CYFER_CIPHER_RC6:
			CYFER_RC6_Init(&ctx->u.rc6, key);
			encrypt = CYFER_RC6_Encrypt; decrypt = CYFER_RC6_Decrypt; cctx = &ctx->u.rc6;
			break;
		case CYFER_CIPHER_IDEA:
			CYFER_IDEA_Init(&ctx->u.idea, key);
			encrypt = CYFER_IDEA_Encrypt; decrypt = CYFER_IDEA_Decrypt; cctx = &ctx->u.idea;
			break;
		case CYFER_CIPHER_AES:
			CYFER_AES_Init(&ctx->u.aes, key);
			encrypt = CYFER_AES_Encrypt; decrypt = CYFER_AES_Decrypt; cctx = &ctx->u.aes;
			break;
		case CYFER_CIPHER_DEAL:
			CYFER_DEAL_Init(&ctx->u.deal, key);
			encrypt = CYFER_DEAL_Encrypt; decrypt = CYFER_DEAL_Decrypt; cctx = &ctx->u.deal;
			break;
		case CYFER_CIPHER_THREEWAY:
			CYFER_THREEWAY_Init(&ctx->u.threeway, key);
			encrypt = CYFER_THREEWAY_Encrypt; decrypt = CYFER_THREEWAY_Decrypt; cctx = &ctx->u.threeway;
			break;
		default:
			free(ctx); return NULL;
	}

	if (CYFER_BlockMode_Init(mode, &ctx->mctx, cctx, encrypt, decrypt, ivec, len)) {
		free(ctx); return NULL;
	}
		
	return ctx;
}


CYFER_API void CYFER_BlockCipher_Encrypt(CYFER_BLOCK_CIPHER_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	CYFER_BlockMode_Encrypt(&ctx->mctx, input, output);
}

CYFER_API void CYFER_BlockCipher_Decrypt(CYFER_BLOCK_CIPHER_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	CYFER_BlockMode_Decrypt(&ctx->mctx, input, output);
}

CYFER_API void CYFER_BlockCipher_Finish(CYFER_BLOCK_CIPHER_CTX *ctx)
{
	CYFER_BlockMode_Finish(&ctx->mctx);
	switch (ctx->type) {
		case CYFER_CIPHER_BLOWFISH: CYFER_BLOWFISH_Finish(&ctx->u.blowfish); break;
		case CYFER_CIPHER_DES: CYFER_DES_Finish(&ctx->u.des); break;
		case CYFER_CIPHER_DESX: CYFER_DESX_Finish(&ctx->u.desx); break;
		case CYFER_CIPHER_TRIPLEDES: CYFER_TRIPLEDES_Finish(&ctx->u.tripledes); break;
		case CYFER_CIPHER_RC2: CYFER_RC2_Finish(&ctx->u.rc2); break;
		case CYFER_CIPHER_RC5: CYFER_RC5_Finish(&ctx->u.rc5); break;
		case CYFER_CIPHER_RC6: CYFER_RC6_Finish(&ctx->u.rc6); break;
		case CYFER_CIPHER_IDEA: CYFER_IDEA_Finish(&ctx->u.idea); break;
		case CYFER_CIPHER_AES: CYFER_AES_Finish(&ctx->u.aes); break;
		case CYFER_CIPHER_DEAL: CYFER_DEAL_Finish(&ctx->u.deal); break;
		case CYFER_CIPHER_THREEWAY: CYFER_THREEWAY_Finish(&ctx->u.threeway); break;
		default: return;
	}
	free(ctx);
}

CYFER_API CYFER_StreamCipher_t *CYFER_StreamCipher_Get_Supported(void)
{
	return CYFER_StreamCiphers;
}

CYFER_API int CYFER_StreamCipher_Select(const char *name, size_t *keylen, size_t *minkey)
{
	int i;
	for (i = 0; CYFER_StreamCiphers[i].type != CYFER_CIPHER_NONE; i++)
		if (!strcmp(name, CYFER_StreamCiphers[i].name)) break;
	if (keylen) *keylen = CYFER_StreamCiphers[i].keylen;
	if (minkey) *minkey = CYFER_StreamCiphers[i].minkey;
	return CYFER_StreamCiphers[i].type;
}


CYFER_API CYFER_STREAM_CIPHER_CTX *CYFER_StreamCipher_Init(int type, const unsigned char *key, size_t keylen)
{
	CYFER_STREAM_CIPHER_CTX *ctx;
	int idx;

	for (idx = 0; CYFER_StreamCiphers[idx].type != CYFER_CIPHER_NONE; idx++)
		if (type == CYFER_StreamCiphers[idx].type) break;
	if (CYFER_StreamCiphers[idx].type == CYFER_CIPHER_NONE) return NULL;

	if ((keylen < CYFER_StreamCiphers[idx].minkey) || (keylen > CYFER_StreamCiphers[idx].keylen)) return NULL;

	ctx = malloc(sizeof(CYFER_STREAM_CIPHER_CTX));
	if (!ctx) return NULL;

	ctx->type = type;
	switch (type) {
		case CYFER_CIPHER_RC4: CYFER_RC4_Init(&ctx->u.rc4, key, keylen); break;
		default:
			free(ctx); return NULL;
	}
	return ctx;
}


CYFER_API void CYFER_StreamCipher_Encrypt(CYFER_STREAM_CIPHER_CTX *ctx, const unsigned char *input, unsigned char *output, size_t length)
{
	switch (ctx->type) {
		case CYFER_CIPHER_RC4: CYFER_RC4_Encrypt(&ctx->u.rc4, input, output, length); return;
	}
}


CYFER_API void CYFER_StreamCipher_Decrypt(CYFER_STREAM_CIPHER_CTX *ctx, const unsigned char *input, unsigned char *output, size_t length)
{
	switch (ctx->type) {
		case CYFER_CIPHER_RC4: CYFER_RC4_Decrypt(&ctx->u.rc4, input, output, length); return;
	}
}


CYFER_API void CYFER_StreamCipher_Finish(CYFER_STREAM_CIPHER_CTX *ctx)
{
	switch (ctx->type) {
		case CYFER_CIPHER_RC4: CYFER_RC4_Finish(&ctx->u.rc4); break;
		default: return;
	}
	free(ctx);
}


