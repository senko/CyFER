#ifndef _MD5_H_
#define _MD5_H_

#include <util.h>

typedef struct {
	u32 h1, h2, h3, h4;
	u64 length;
	u8 *buffer;
	size_t buflen;
} MD5_CTX;

#ifdef __cplusplus
extern "C" {
#endif

CYFER_API void CYFER_MD5_Init(MD5_CTX *ctx);
CYFER_API void CYFER_MD5_Update(MD5_CTX *ctx, const unsigned char *data, size_t len);
CYFER_API void CYFER_MD5_Finish(MD5_CTX *ctx, unsigned char *md);
CYFER_API void CYFER_MD5(const unsigned char *data, size_t len, unsigned char *md);

#ifdef __cplusplus
};
#endif

#endif /* _MD5_H_ */

