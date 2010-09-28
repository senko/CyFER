#ifndef _BLOWFISH_H_
#define _BLOWFISH_H_

#include <util.h>

typedef struct {
	u32 P[18];
	u32 sbox[4][256];
} BLOWFISH_CTX;

#ifdef __cplusplus
extern "C" {
#endif

CYFER_API void CYFER_BLOWFISH_Init(BLOWFISH_CTX *ctx, const unsigned char *key, size_t keylen);
CYFER_API void CYFER_BLOWFISH_Encrypt(BLOWFISH_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_BLOWFISH_Decrypt(BLOWFISH_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_BLOWFISH_Finish(BLOWFISH_CTX *ctx);

#ifdef __cplusplus
};
#endif

#endif /* _BLOWFISH_H_ */

