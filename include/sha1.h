#ifndef _SHA1_H_
#define _SHA1_H_

#include <util.h>

typedef struct {
	u32 h1, h2, h3, h4, h5;
	u64 length;
	u8 *buffer;
	size_t buflen;
} SHA1_CTX;

#ifdef __cplusplus
extern "C" {
#endif

CYFER_API void CYFER_SHA1_Init(SHA1_CTX *ctx);
CYFER_API void CYFER_SHA1_Update(SHA1_CTX *ctx, const unsigned char *data, size_t len);
CYFER_API void CYFER_SHA1_Finish(SHA1_CTX *ctx, unsigned char *md);
CYFER_API void CYFER_SHA1(const unsigned char *data, size_t len, unsigned char *md);

#ifdef __cplusplus
};
#endif

#endif /* _SHA1_H_ */

