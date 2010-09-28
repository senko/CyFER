#include <stdio.h>
#include <string.h>
#include <util.h>
#include <cyfer/hash.h>

static CYFER_Hash_t CYFER_HashTypes[] = {
	{ CYFER_HASH_MD4, "MD4", 16 },
	{ CYFER_HASH_MD5, "MD5", 16 },
	{ CYFER_HASH_SHA1, "SHA-1", 20 },
	{ CYFER_HASH_SHA256, "SHA-256", 32 },
	{ CYFER_HASH_RMD160, "RIPEMD-160", 20 },
	{ CYFER_HASH_ADLER32, "Adler-32", 4 },
	{ CYFER_HASH_SNEFRU, "Snefru", 4 * SNEFRU_OUTPUT_SIZE },
	{ CYFER_HASH_CRC32, "CRC-32", 4 },
	{ CYFER_HASH_MD2, "MD2", 16 },
	{ CYFER_HASH_NONE, NULL, 0 }
};

CYFER_API CYFER_Hash_t *CYFER_Hash_Get_Supported(void)
{
	return CYFER_HashTypes;
}

CYFER_API int CYFER_Hash_Select(const char *name, size_t *length)
{
	int i;
	for (i = 0; CYFER_HashTypes[i].type != CYFER_HASH_NONE; i++)
		if (!strcmp(name, CYFER_HashTypes[i].name)) break;
	if (length) *length = CYFER_HashTypes[i].length;
	return CYFER_HashTypes[i].type;
}


CYFER_API CYFER_HASH_CTX *CYFER_Hash_Init(int type)
{
	CYFER_HASH_CTX *ctx;

	ctx = malloc(sizeof(CYFER_HASH_CTX));
	if (!ctx) return NULL;

	ctx->type = type;
	switch (type) {
		case CYFER_HASH_MD4: CYFER_MD4_Init(&ctx->u.md4); break;
		case CYFER_HASH_MD5: CYFER_MD5_Init(&ctx->u.md5); break;
		case CYFER_HASH_SHA1: CYFER_SHA1_Init(&ctx->u.sha1); break;
		case CYFER_HASH_SHA256: CYFER_SHA256_Init(&ctx->u.sha256); break;
		case CYFER_HASH_RMD160: CYFER_RMD160_Init(&ctx->u.rmd160); break;
		case CYFER_HASH_ADLER32: CYFER_ADLER32_Init(&ctx->u.adler32); break;
		case CYFER_HASH_SNEFRU: CYFER_SNEFRU_Init(&ctx->u.snefru); break;
		case CYFER_HASH_CRC32: CYFER_CRC32_Init(&ctx->u.crc32); break;
		case CYFER_HASH_MD2: CYFER_MD2_Init(&ctx->u.md2); break;
		default:
			free(ctx); return NULL;
	}
	return ctx;
}


CYFER_API void CYFER_Hash_Update(CYFER_HASH_CTX *ctx, const unsigned char *data, size_t len)
{
	switch (ctx->type) {
		case CYFER_HASH_MD4: CYFER_MD4_Update(&ctx->u.md4, data, len); return;
		case CYFER_HASH_MD5: CYFER_MD5_Update(&ctx->u.md5, data, len); return;
		case CYFER_HASH_SHA1: CYFER_SHA1_Update(&ctx->u.sha1, data, len); return;
		case CYFER_HASH_SHA256: CYFER_SHA256_Update(&ctx->u.sha256, data, len); return;
		case CYFER_HASH_RMD160: CYFER_RMD160_Update(&ctx->u.rmd160, data, len); return;
		case CYFER_HASH_ADLER32: CYFER_ADLER32_Update(&ctx->u.adler32, data, len); return;
		case CYFER_HASH_SNEFRU: CYFER_SNEFRU_Update(&ctx->u.snefru, data, len); return;
		case CYFER_HASH_CRC32: CYFER_CRC32_Update(&ctx->u.crc32, data, len); return;
		case CYFER_HASH_MD2: CYFER_MD2_Update(&ctx->u.md2, data, len); return;
	}
}


CYFER_API void CYFER_Hash_Finish(CYFER_HASH_CTX *ctx, unsigned char *md)
{
	switch (ctx->type) {
		case CYFER_HASH_MD4: CYFER_MD4_Finish(&ctx->u.md4, md); break;
		case CYFER_HASH_MD5: CYFER_MD5_Finish(&ctx->u.md5, md); break;
		case CYFER_HASH_SHA1: CYFER_SHA1_Finish(&ctx->u.sha1, md); break;
		case CYFER_HASH_SHA256: CYFER_SHA256_Finish(&ctx->u.sha256, md); break;
		case CYFER_HASH_RMD160: CYFER_RMD160_Finish(&ctx->u.rmd160, md); break;
		case CYFER_HASH_ADLER32: CYFER_ADLER32_Finish(&ctx->u.adler32, md); break;
		case CYFER_HASH_SNEFRU: CYFER_SNEFRU_Finish(&ctx->u.snefru, md); break;
		case CYFER_HASH_CRC32: CYFER_CRC32_Finish(&ctx->u.crc32, md); break;
		case CYFER_HASH_MD2: CYFER_MD2_Finish(&ctx->u.md2, md); break;
		default: return;
	}
	free(ctx);
}


CYFER_API int CYFER_Hash(int type, const unsigned char *data, size_t len, unsigned char *md)
{
	switch (type) {
		case CYFER_HASH_MD4: CYFER_MD4(data, len, md); return 0;
		case CYFER_HASH_MD5: CYFER_MD5(data, len, md); return 0;
		case CYFER_HASH_SHA1: CYFER_SHA1(data, len, md); return 0;
		case CYFER_HASH_SHA256: CYFER_SHA256(data, len, md); return 0;
		case CYFER_HASH_RMD160: CYFER_RMD160(data, len, md); return 0;
		case CYFER_HASH_ADLER32: CYFER_ADLER32(data, len, md); return 0;
		case CYFER_HASH_SNEFRU: CYFER_SNEFRU(data, len, md); return 0;
		case CYFER_HASH_CRC32: CYFER_CRC32(data, len, md); return 0;
		case CYFER_HASH_MD2: CYFER_MD2(data, len, md); return 0;
	}
	return -1;
}

