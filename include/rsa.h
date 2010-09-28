#ifndef _RSA_H_
#define _RSA_H_

#include <bignum.h>

typedef struct {
	size_t privlen;
	size_t publen;
	bignum_t e;
	bignum_t d;
	bignum_t n;
} RSA_CTX;

#ifdef __cplusplus
extern "C" {
#endif

CYFER_API void CYFER_RSA_Init(RSA_CTX *ctx);
CYFER_API void CYFER_RSA_Finish(RSA_CTX *ctx);
CYFER_API void CYFER_RSA_Generate_Key(RSA_CTX *ctx, size_t keylen);
CYFER_API void CYFER_RSA_Size(RSA_CTX *ctx, size_t *pt_len, size_t *ct_len);
CYFER_API void CYFER_RSA_KeySize(RSA_CTX *ctx, size_t *privlen, size_t *publen);
CYFER_API void CYFER_RSA_Export_Key(RSA_CTX *ctx, unsigned char *priv, unsigned char *pub);
CYFER_API bool CYFER_RSA_Import_Key(RSA_CTX *ctx, unsigned char *priv, size_t privlen, unsigned char *pub, size_t publen);
CYFER_API void CYFER_RSA_Encrypt(RSA_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_RSA_Decrypt(RSA_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_RSA_Sign(RSA_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API bool CYFER_RSA_Verify(RSA_CTX *ctx, const unsigned char *signature, const unsigned char *message);

#ifdef __cplusplus
};
#endif

#endif /* _RSA_H_ */

