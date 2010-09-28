#include <string.h>
#include <util.h>
#include <cyfer/pk.h>

static CYFER_Pk_t CYFER_PkAlgorithms[] = {
	{ CYFER_PK_RSA, "RSA", true, true },
	{ CYFER_PK_ELGAMAL, "ElGamal", true, true },
	{ CYFER_PK_LUC, "LUC", true, true },
	{ CYFER_PK_NONE, NULL, false, false }
};

CYFER_API CYFER_Pk_t *CYFER_Pk_Get_Supported(void)
{
	return CYFER_PkAlgorithms;
}

CYFER_API int CYFER_Pk_Select(const char *name, bool *enc, bool *sig)
{
	int i;
	for (i = 0; CYFER_PkAlgorithms[i].type != CYFER_PK_NONE; i++)
		if (!strcmp(name, CYFER_PkAlgorithms[i].name)) break;
	if (enc) *enc = CYFER_PkAlgorithms[i].encryption;
	if (sig) *sig = CYFER_PkAlgorithms[i].signature;
	return CYFER_PkAlgorithms[i].type;
}

CYFER_API CYFER_PK_CTX *CYFER_Pk_Init(int type)
{
	CYFER_PK_CTX *ctx;
	
	ctx = malloc(sizeof(CYFER_PK_CTX));
	if (!ctx) return NULL;

	ctx->type = type;
	switch (type) {
		case CYFER_PK_RSA: CYFER_RSA_Init(&ctx->u.rsa); break;
		case CYFER_PK_ELGAMAL: CYFER_ELGAMAL_Init(&ctx->u.elgamal); break;
		case CYFER_PK_LUC: CYFER_LUC_Init(&ctx->u.luc); break;
		default:
		   free(ctx); return NULL;
	}
	return ctx;
}

CYFER_API void CYFER_Pk_Finish(CYFER_PK_CTX *ctx)
{
	switch (ctx->type) {
		case CYFER_PK_RSA: CYFER_RSA_Finish(&ctx->u.rsa); break;
		case CYFER_PK_ELGAMAL: CYFER_ELGAMAL_Finish(&ctx->u.elgamal); break;
		case CYFER_PK_LUC: CYFER_LUC_Finish(&ctx->u.luc); break;
		default: return;
	}
	free(ctx);
}

CYFER_API void CYFER_Pk_Generate_Key(CYFER_PK_CTX *ctx, size_t keylen)
{
	if (!keylen) return;

	switch (ctx->type) {
		case CYFER_PK_RSA: CYFER_RSA_Generate_Key(&ctx->u.rsa, keylen); return;
		case CYFER_PK_ELGAMAL: CYFER_ELGAMAL_Generate_Key(&ctx->u.elgamal, keylen); return;
		case CYFER_PK_LUC: CYFER_LUC_Generate_Key(&ctx->u.luc, keylen); return;
	}
}

CYFER_API void CYFER_Pk_Size(CYFER_PK_CTX *ctx, size_t *pt_len, size_t *ct_len)
{
	switch (ctx->type) {
		case CYFER_PK_RSA: CYFER_RSA_Size(&ctx->u.rsa, pt_len, ct_len); return;
		case CYFER_PK_ELGAMAL: CYFER_ELGAMAL_Size(&ctx->u.elgamal, pt_len, ct_len); return;
		case CYFER_PK_LUC: CYFER_LUC_Size(&ctx->u.luc, pt_len, ct_len); return;
	}
}

CYFER_API void CYFER_Pk_KeySize(CYFER_PK_CTX *ctx, size_t *privlen, size_t *publen)
{
	switch (ctx->type) {
		case CYFER_PK_RSA: CYFER_RSA_KeySize(&ctx->u.rsa, privlen, publen); return;
		case CYFER_PK_ELGAMAL: CYFER_ELGAMAL_KeySize(&ctx->u.elgamal, privlen, publen); return;
		case CYFER_PK_LUC: CYFER_LUC_KeySize(&ctx->u.luc, privlen, publen); return;
	}
}

CYFER_API void CYFER_Pk_Export_Key(CYFER_PK_CTX *ctx, unsigned char *priv, unsigned char *pub)
{
	switch (ctx->type) {
		case CYFER_PK_RSA: CYFER_RSA_Export_Key(&ctx->u.rsa, priv, pub); return;
		case CYFER_PK_ELGAMAL: CYFER_ELGAMAL_Export_Key(&ctx->u.elgamal, priv, pub); return;
		case CYFER_PK_LUC: CYFER_LUC_Export_Key(&ctx->u.luc, priv, pub); return;
	}
}

CYFER_API bool CYFER_Pk_Import_Key(CYFER_PK_CTX *ctx, unsigned char *priv, size_t privlen, unsigned char *pub, size_t publen)
{
	switch (ctx->type) {
		case CYFER_PK_RSA: return CYFER_RSA_Import_Key(&ctx->u.rsa, priv, privlen, pub, publen);
		case CYFER_PK_ELGAMAL: return CYFER_ELGAMAL_Import_Key(&ctx->u.elgamal, priv, privlen, pub, publen); 
		case CYFER_PK_LUC: return CYFER_LUC_Import_Key(&ctx->u.luc, priv, privlen, pub, publen);
	}
	return false;
}

CYFER_API void CYFER_Pk_Encrypt(CYFER_PK_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	switch (ctx->type) {
		case CYFER_PK_RSA: CYFER_RSA_Encrypt(&ctx->u.rsa, input, output); return;
		case CYFER_PK_ELGAMAL: CYFER_ELGAMAL_Encrypt(&ctx->u.elgamal, input, output); return;
		case CYFER_PK_LUC: CYFER_LUC_Encrypt(&ctx->u.luc, input, output); return;
	}
}

CYFER_API void CYFER_Pk_Decrypt(CYFER_PK_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	switch (ctx->type) {
		case CYFER_PK_RSA: CYFER_RSA_Decrypt(&ctx->u.rsa, input, output); return;
		case CYFER_PK_ELGAMAL: CYFER_ELGAMAL_Decrypt(&ctx->u.elgamal, input, output); return;
		case CYFER_PK_LUC: CYFER_LUC_Decrypt(&ctx->u.luc, input, output); return;
	}
}

CYFER_API void CYFER_Pk_Sign(CYFER_PK_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	switch (ctx->type) {
		case CYFER_PK_RSA: CYFER_RSA_Sign(&ctx->u.rsa, input, output); return;
		case CYFER_PK_ELGAMAL: CYFER_ELGAMAL_Sign(&ctx->u.elgamal, input, output); return;
		case CYFER_PK_LUC: CYFER_LUC_Sign(&ctx->u.luc, input, output); return;
	}
}

CYFER_API bool CYFER_Pk_Verify(CYFER_PK_CTX *ctx, const unsigned char *signature, const unsigned char *message)
{
	switch (ctx->type) {
		case CYFER_PK_RSA: return CYFER_RSA_Verify(&ctx->u.rsa, signature, message);
		case CYFER_PK_ELGAMAL: return CYFER_ELGAMAL_Verify(&ctx->u.elgamal, signature, message);
		case CYFER_PK_LUC: return CYFER_LUC_Verify(&ctx->u.luc, signature, message);
	}
	return false;
}

