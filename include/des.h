#ifndef _DES_H_
#define _DES_H_

#include <util.h>

typedef struct {
	u64 K[16];
} DES_CTX;

#ifdef __cplusplus
extern "C" {
#endif
	
CYFER_API void CYFER_DES_Init(DES_CTX *ctx, const unsigned char *key);
CYFER_API void CYFER_DES_Encrypt(DES_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_DES_Decrypt(DES_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_DES_Finish(DES_CTX *ctx);

#ifdef __cplusplus
};
#endif

#endif /* _DES_H_ */

