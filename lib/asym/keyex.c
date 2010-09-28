#include <string.h>
#include <util.h>
#include <cyfer/keyex.h>

static CYFER_KeyEx_t CYFER_KeyEx_Algorithms[] = {
	{ CYFER_KEYEX_DH, "DH" },
	{ CYFER_KEYEX_NONE, NULL }
};

CYFER_API CYFER_KeyEx_t *CYFER_KeyEx_Get_Supported(void)
{
	return CYFER_KeyEx_Algorithms;
}

CYFER_API int CYFER_KeyEx_Select(const char *name)
{
	int i;
	for (i = 0; CYFER_KeyEx_Algorithms[i].type != CYFER_KEYEX_NONE; i++)
		if (!strcmp(name, CYFER_KeyEx_Algorithms[i].name)) break;
	return CYFER_KeyEx_Algorithms[i].type;
}

CYFER_API CYFER_KEYEX_CTX *CYFER_KeyEx_Init(int type)
{
	CYFER_KEYEX_CTX *ctx;
	
	ctx = malloc(sizeof(CYFER_KEYEX_CTX));
	if (!ctx) return NULL;

	ctx->type = type;
	switch (type) {
		case CYFER_KEYEX_DH: CYFER_DH_Init(&ctx->u.dh); break;
		default:
			 free(ctx); return NULL;
	}
	return ctx;
}

CYFER_API void CYFER_KeyEx_Finish(CYFER_KEYEX_CTX *ctx)
{
	switch (ctx->type) {
		case CYFER_KEYEX_DH: CYFER_DH_Finish(&ctx->u.dh); break;
		default: return;
	}
	free(ctx);
}

CYFER_API void CYFER_KeyEx_Generate_Key(CYFER_KEYEX_CTX *ctx)
{
	switch (ctx->type) {
		case CYFER_KEYEX_DH: CYFER_DH_Generate_Key(&ctx->u.dh);
	}
}

CYFER_API void CYFER_KeyEx_KeySize(CYFER_KEYEX_CTX *ctx, size_t *privlen, size_t *publen)
{
	switch (ctx->type) {
		case CYFER_KEYEX_DH: CYFER_DH_KeySize(&ctx->u.dh, privlen, publen);
	}
}

CYFER_API bool CYFER_KeyEx_Compute_Key(CYFER_KEYEX_CTX *ctx, unsigned char *other, size_t len)
{
	switch (ctx->type) {
		case CYFER_KEYEX_DH: return CYFER_DH_Compute_Key(&ctx->u.dh, other, len);
	}
	return false;
}

CYFER_API void CYFER_KeyEx_Public_Key(CYFER_KEYEX_CTX *ctx, unsigned char *key)
{
	switch (ctx->type) {
		case CYFER_KEYEX_DH: CYFER_DH_Public_Key(&ctx->u.dh, key);
	}
}

CYFER_API void CYFER_KeyEx_Shared_Key(CYFER_KEYEX_CTX *ctx, unsigned char *key, size_t len)
{
	switch (ctx->type) {
		case CYFER_KEYEX_DH: CYFER_DH_Shared_Key(&ctx->u.dh, key, len);
	}
}

