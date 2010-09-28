#include <util.h>
#include <stdlib.h>
#include <string.h>

#include <modes.h>

static CYFER_BlockMode_t CYFER_BlockCipherModes[] = {
	{ CYFER_MODE_ECB, "ECB", 0 },
	{ CYFER_MODE_CBC, "CBC", 0 },
	{ CYFER_MODE_CFB, "CFB", 1 },
	{ CYFER_MODE_OFB, "OFB", 1 },
	{ CYFER_MODE_NONE, NULL, 0 },
};

static inline void xorblk(unsigned char *dest, const unsigned char *src1, const unsigned char *src2, size_t len)
{
	while (len--) *dest++ = *src1++ ^ *src2++;
}

/* interface */

CYFER_API CYFER_BlockMode_t *CYFER_BlockCipher_Get_SupportedModes(void)
{
	return CYFER_BlockCipherModes;
}

CYFER_API int CYFER_BlockCipher_SelectMode(const char *name, size_t *length)
{
	int i;
	for (i = 0; CYFER_BlockCipherModes[i].type != CYFER_MODE_NONE; i++)
		if (!strcmp(name, CYFER_BlockCipherModes[i].name)) break;
	if (length) *length = CYFER_BlockCipherModes[i].length;
	return CYFER_BlockCipherModes[i].type;
}

/* implementation */

int CYFER_BlockMode_Init(int mode, CYFER_BLOCK_MODE_CTX *ctx, void *cipher_ctx, void *encrypt, void *decrypt, const unsigned char *ivec, size_t length)
{
	switch (mode) {
		case CYFER_MODE_ECB:
		case CYFER_MODE_CBC:
		case CYFER_MODE_CFB:
		case CYFER_MODE_OFB: break;
		default: return -1;	
	}

	ctx->mode = mode;
	ctx->context = cipher_ctx;
	ctx->encrypt = (cyfer_crypt_handler_t) encrypt;
	ctx->decrypt = (cyfer_crypt_handler_t) decrypt;
	ctx->length = length;
	ctx->chain = malloc(length);
	ctx->outbuf = malloc(length);
	if (ivec) 
		memcpy(ctx->chain, ivec, length);
	else
		memset(ctx->chain, 0, length);

	return 0;
}


void CYFER_BlockMode_Encrypt(CYFER_BLOCK_MODE_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	switch (ctx->mode) {
		case CYFER_MODE_ECB:
			ctx->encrypt(ctx->context, input, output);
			return;
		case CYFER_MODE_CBC:
			xorblk(ctx->chain, ctx->chain, input, ctx->length);
			ctx->encrypt(ctx->context, ctx->chain, output);
			memcpy(ctx->chain, output, ctx->length);
			return;
		case CYFER_MODE_CFB:
			ctx->encrypt(ctx->context, ctx->chain, ctx->outbuf);
			*output = *input ^ *(ctx->outbuf);
			memmove(ctx->chain, ctx->chain + 1, ctx->length - 1);
			ctx->chain[ctx->length - 1] = *output;
			return;
		case CYFER_MODE_OFB:
			ctx->encrypt(ctx->context, ctx->chain, ctx->outbuf);
			*output = *input ^ *(ctx->outbuf);
			memcpy(ctx->chain, ctx->outbuf, ctx->length);
			return;
	}
}


void CYFER_BlockMode_Decrypt(CYFER_BLOCK_MODE_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	switch (ctx->mode) {
		case CYFER_MODE_ECB:
			ctx->decrypt(ctx->context, input, output);
			return;
		case CYFER_MODE_CBC:
			ctx->decrypt(ctx->context, input, output);
			xorblk(output, ctx->chain, output, ctx->length);
	 		memcpy(ctx->chain, input, ctx->length);
			return;
		case CYFER_MODE_CFB:
			ctx->encrypt(ctx->context, ctx->chain, ctx->outbuf);
			*output = *input ^ *(ctx->outbuf);
			memmove(ctx->chain, ctx->chain + 1, ctx->length - 1);
			ctx->chain[ctx->length - 1] = *input; 
			return;
		case CYFER_MODE_OFB:
			ctx->encrypt(ctx->context, ctx->chain, ctx->outbuf);
			*output = *input ^ *(ctx->outbuf);
			memcpy(ctx->chain, ctx->outbuf, ctx->length);
			return;
	}
}


void CYFER_BlockMode_Finish(CYFER_BLOCK_MODE_CTX *ctx)
{
	free(ctx->chain);
	free(ctx->outbuf);
}

