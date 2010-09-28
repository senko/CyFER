#ifndef _LUC_H_
#define _LUC_H_

#include <bignum.h>

typedef struct {
	size_t privlen;
	size_t publen;
	bignum_t e;
	bignum_t d;
	bignum_t n;
} LUC_CTX;

#ifdef __cplusplus
extern "C" {
#endif
	
CYFER_API void CYFER_LUC_Init(LUC_CTX *ctx);
CYFER_API void CYFER_LUC_Finish(LUC_CTX *ctx);
CYFER_API void CYFER_LUC_Generate_Key(LUC_CTX *ctx, size_t keylen);
CYFER_API void CYFER_LUC_Size(LUC_CTX *ctx, size_t *pt_len, size_t *ct_len);
CYFER_API void CYFER_LUC_KeySize(LUC_CTX *ctx, size_t *privlen, size_t *publen);
CYFER_API void CYFER_LUC_Export_Key(LUC_CTX *ctx, unsigned char *priv, unsigned char *pub);
CYFER_API bool CYFER_LUC_Import_Key(LUC_CTX *ctx, unsigned char *priv, size_t privlen, unsigned char *pub, size_t publen);
CYFER_API void CYFER_LUC_Encrypt(LUC_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_LUC_Decrypt(LUC_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_LUC_Sign(LUC_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API bool CYFER_LUC_Verify(LUC_CTX *ctx, const unsigned char *signature, const unsigned char *message);

#ifdef __cplusplus
};
#endif

#endif /* _LUC_H_ */

