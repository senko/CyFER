#ifndef _TRIPLEDES_H_
#define _TRIPLEDES_H_

#include <des.h>

typedef struct {
	DES_CTX a, b, c;
} TRIPLEDES_CTX;

#ifdef __cplusplus
extern "C" {
#endif

CYFER_API void CYFER_TRIPLEDES_Init(TRIPLEDES_CTX *ctx, const unsigned char *key);
CYFER_API void CYFER_TRIPLEDES_Encrypt(TRIPLEDES_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_TRIPLEDES_Decrypt(TRIPLEDES_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_TRIPLEDES_Finish(TRIPLEDES_CTX *ctx);

#ifdef __cplusplus
};
#endif

#endif /* _TRIPLEDES_H_ */

