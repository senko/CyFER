#ifndef _RMD160_H_
#define _RMD160_H_

#include <util.h>

typedef struct {
	u32 h1, h2, h3, h4, h5;
	u64 length;
	u8 *buffer;
	size_t buflen;
} RMD160_CTX;

CYFER_API void CYFER_RMD160_Init(RMD160_CTX *ctx);
CYFER_API void CYFER_RMD160_Update(RMD160_CTX *ctx, const unsigned char *data, size_t len);
CYFER_API void CYFER_RMD160_Finish(RMD160_CTX *ctx, unsigned char *md);
CYFER_API void CYFER_RMD160(const unsigned char *data, size_t len, unsigned char *md);

#endif /* _RMD160_H_ */

