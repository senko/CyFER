#ifndef _RC5_H_
#define _RC5_H_

#include <util.h>

typedef struct {
	u32 S[26];
} RC5_CTX;

#ifdef __cplusplus
extern "C" {
#endif

CYFER_API void CYFER_RC5_Init(RC5_CTX *ctx, const unsigned char *key);
CYFER_API void CYFER_RC5_Encrypt(RC5_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_RC5_Decrypt(RC5_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_RC5_Finish(RC5_CTX *ctx);

#ifdef __cplusplus
};
#endif

#endif /* _RC5_H_ */

