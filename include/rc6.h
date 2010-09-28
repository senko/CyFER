#ifndef _RC6_H_
#define _RC6_H_

#include <util.h>

typedef struct {
	u32 S[44];
} RC6_CTX;

#ifdef __cplusplus
extern "C" {
#endif

CYFER_API void CYFER_RC6_Init(RC6_CTX *ctx, const unsigned char *key);
CYFER_API void CYFER_RC6_Encrypt(RC6_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_RC6_Decrypt(RC6_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_RC6_Finish(RC6_CTX *ctx);

#ifdef __cplusplus
};
#endif

#endif /* _RC6_H_ */

