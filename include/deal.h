#ifndef _DEAL_H_
#define _DEAL_H_

#include <des.h>

typedef struct {
	DES_CTX des[6];
} DEAL_CTX;

#ifdef __cplusplus
extern "C" {
#endif

CYFER_API void CYFER_DEAL_Init(DEAL_CTX *ctx, const unsigned char *key);
CYFER_API void CYFER_DEAL_Encrypt(DEAL_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_DEAL_Decrypt(DEAL_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_DEAL_Finish(DEAL_CTX *ctx);

#ifdef __cplusplus
};
#endif

#endif /* _DEAL_H_ */

