#ifndef _ADLER32_H_
#define _ADLER32_H_

#include <util.h>

typedef struct {
	u32 s1, s2;
} ADLER32_CTX;

#ifdef __cplusplus
extern "C" {
#endif 

CYFER_API void CYFER_ADLER32_Init(ADLER32_CTX *ctx);
CYFER_API void CYFER_ADLER32_Update(ADLER32_CTX *ctx, const unsigned char *data, size_t len);
CYFER_API void CYFER_ADLER32_Finish(ADLER32_CTX *ctx, unsigned char *md);
CYFER_API void CYFER_ADLER32(const unsigned char *data, size_t len, unsigned char *md);

#ifdef __cplusplus
};
#endif 

#endif /* _ADLER32_H_ */

