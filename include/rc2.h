#ifndef _RC2_H_
#define _RC2_H_

#include <util.h>

typedef struct {
	u16 K[16];
} RC2_CTX;

#ifdef __cplusplus
extern "C" {
#endif
	
CYFER_API void CYFER_RC2_Init(RC2_CTX *ctx, const unsigned char *key, size_t keylen);
CYFER_API void CYFER_RC2_Encrypt(RC2_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_RC2_Decrypt(RC2_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_RC2_Finish(RC2_CTX *ctx);

#ifdef __cplusplus
};
#endif

#endif /* _RC2_H_ */

