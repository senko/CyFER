#ifndef _CRC32_H_
#define _CRC32_H_

#include <util.h>

typedef struct {
	u32 crc;
} CRC32_CTX;

#ifdef __cplusplus
extern "C" {
#endif
	
CYFER_API void CYFER_CRC32_Init(CRC32_CTX *ctx);
CYFER_API void CYFER_CRC32_Update(CRC32_CTX *ctx, const unsigned char *data, size_t len);
CYFER_API void CYFER_CRC32_Finish(CRC32_CTX *ctx, unsigned char *md);
CYFER_API void CYFER_CRC32(const unsigned char *data, size_t len, unsigned char *md);

#ifdef __cplusplus
};
#endif

#endif /* _CRC32_H_ */

