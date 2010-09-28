#ifndef _RC4_H_
#define _RC4_H_

#include <util.h>

typedef struct {
	u8 state[256];
	int i, f;
} RC4_CTX;

#ifdef __cplusplus
extern "C" {
#endif
	
CYFER_API void CYFER_RC4_Init(RC4_CTX *ctx, const unsigned char *key, size_t keylen);
CYFER_API void CYFER_RC4_Encrypt(RC4_CTX *ctx, const unsigned char *input, unsigned char *output, size_t len);
CYFER_API void CYFER_RC4_Decrypt(RC4_CTX *ctx, const unsigned char *input, unsigned char *output, size_t len);
CYFER_API void CYFER_RC4_Finish(RC4_CTX *ctx);

#ifdef __cplusplus
};
#endif

#endif /* _RC4_H_ */

