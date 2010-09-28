#ifndef _MD4_H_
#define _MD4_H_

#include <util.h>

typedef struct {
	u32 h1, h2, h3, h4;
	u64 length;
	u8 *buffer;
	size_t buflen;
} MD4_CTX;

#ifdef __cplusplus
extern "C" {
#endif
	
CYFER_API void CYFER_MD4_Init(MD4_CTX *ctx);
CYFER_API void CYFER_MD4_Update(MD4_CTX *ctx, const unsigned char *data, size_t len);
CYFER_API void CYFER_MD4_Finish(MD4_CTX *ctx, unsigned char *md);
CYFER_API void CYFER_MD4(const unsigned char *data, size_t len, unsigned char *md);

#ifdef __cplusplus
};
#endif

#endif /* _MD4_H_ */

