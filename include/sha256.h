#ifndef _SHA256_H_
#define _SHA256_H_

#include <util.h>

typedef struct {
	u32 h[8];
	u64 length;
	u8 *buffer;
	size_t buflen;
} SHA256_CTX;

#ifdef __cplusplus
extern "C" {
#endif

CYFER_API void CYFER_SHA256_Init(SHA256_CTX *ctx);
CYFER_API void CYFER_SHA256_Update(SHA256_CTX *ctx, const unsigned char *data, size_t len);
CYFER_API void CYFER_SHA256_Finish(SHA256_CTX *ctx, unsigned char *md);
CYFER_API void CYFER_SHA256(const unsigned char *data, size_t len, unsigned char *md);

#ifdef __cplusplus
};
#endif

#endif /* _SHA256_H_ */

