#ifndef _THREEWAY_H_
#define _THREEWAY_H_

#include <util.h>

typedef struct {
	u32 key[3];
	u32 ikey[3];
} THREEWAY_CTX;

#ifdef __cplusplus
extern "C" {
#endif

CYFER_API void CYFER_THREEWAY_Init(THREEWAY_CTX *ctx, const unsigned char *key);
CYFER_API void CYFER_THREEWAY_Encrypt(THREEWAY_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_THREEWAY_Decrypt(THREEWAY_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_THREEWAY_Finish(THREEWAY_CTX *ctx);

#ifdef __cplusplus
};
#endif

#endif /* _THREEWAY_H_ */

