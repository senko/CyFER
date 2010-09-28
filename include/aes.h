#ifndef _AES_H_
#define _AES_H_

#include <util.h>

typedef struct {
	u8 K[11][16];
} AES_CTX;

#ifdef __cplusplus
extern "C" {
#endif

CYFER_API void CYFER_AES_Init(AES_CTX *ctx, const unsigned char *key);
CYFER_API void CYFER_AES_Encrypt(AES_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_AES_Decrypt(AES_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_AES_Finish(AES_CTX *ctx);

#ifdef __cplusplus
};
#endif

#endif /* _AES_H_ */

