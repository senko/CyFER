#ifndef _DESX_H_
#define _DESX_H_

#include <des.h>

typedef struct {
	DES_CTX des;
	u8 prewhitening[8];
	u8 postwhitening[8];
} DESX_CTX;

#ifdef __cplusplus
extern "C" {
#endif
	
CYFER_API void CYFER_DESX_Init(DESX_CTX *ctx, const unsigned char *key);
CYFER_API void CYFER_DESX_Encrypt(DESX_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_DESX_Decrypt(DESX_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_DESX_Finish(DESX_CTX *ctx);

#ifdef __cplusplus
};
#endif

#endif /* _DESX_H_ */

