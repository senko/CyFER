#ifndef _ELGAMAL_H_
#define _ELGAMAL_H_

#include <bignum.h>

typedef struct {
	randstate_t state;
	size_t publen;
	size_t privlen;
	bignum_t g;
	bignum_t p;
	bignum_t x;
	bignum_t y;
} ELGAMAL_CTX;

#ifdef __cplusplus
extern "C" {
#endif
	
CYFER_API void CYFER_ELGAMAL_Init(ELGAMAL_CTX *ctx);
CYFER_API void CYFER_ELGAMAL_Finish(ELGAMAL_CTX *ctx);
CYFER_API void CYFER_ELGAMAL_Generate_Key(ELGAMAL_CTX *ctx, size_t keylen);
CYFER_API void CYFER_ELGAMAL_Size(ELGAMAL_CTX *ctx, size_t *pt_len, size_t *ct_len);
CYFER_API void CYFER_ELGAMAL_KeySize(ELGAMAL_CTX *ctx, size_t *privlen, size_t *publen);
CYFER_API void CYFER_ELGAMAL_Export_Key(ELGAMAL_CTX *ctx, unsigned char *priv, unsigned char *pub);
CYFER_API bool CYFER_ELGAMAL_Import_Key(ELGAMAL_CTX *ctx, unsigned char *priv, size_t privlen, unsigned char *pub, size_t publen);
CYFER_API void CYFER_ELGAMAL_Encrypt(ELGAMAL_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_ELGAMAL_Decrypt(ELGAMAL_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_ELGAMAL_Sign(ELGAMAL_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API bool CYFER_ELGAMAL_Verify(ELGAMAL_CTX *ctx, const unsigned char *signature, const unsigned char *message);

#ifdef __cplusplus
};
#endif

#endif /* _ELGAMAL_H_ */

