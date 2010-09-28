#ifndef _IDEA_H_
#define _IDEA_H_

#include <util.h>

typedef struct {
	u16 K[52];
	u16 Kinv[52];
} IDEA_CTX;

#ifdef __cplusplus
extern "C" {
#endif
	
CYFER_API void CYFER_IDEA_Init(IDEA_CTX *ctx, const unsigned char *key);
CYFER_API void CYFER_IDEA_Encrypt(IDEA_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_IDEA_Decrypt(IDEA_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_IDEA_Finish(IDEA_CTX *ctx);

#ifdef __cplusplus
};
#endif

#endif /* _IDEA_H_ */

