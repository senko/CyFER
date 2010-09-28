#ifndef _SNEFRU_H_
#define _SNEFRU_H_

#include <util.h>

#define SNEFRU_OUTPUT_SIZE 4

typedef struct {
	u64 length;
	u8 *hashbuf;
	u8 *buffer;
	size_t buflen;
} SNEFRU_CTX;

#ifdef __cplusplus
extern "C" {
#endif

CYFER_API void CYFER_SNEFRU_Init(SNEFRU_CTX *ctx);
CYFER_API void CYFER_SNEFRU_Update(SNEFRU_CTX *ctx, const unsigned char *data, size_t len);
CYFER_API void CYFER_SNEFRU_Finish(SNEFRU_CTX *ctx, unsigned char *md);
CYFER_API void CYFER_SNEFRU(const unsigned char *data, size_t len, unsigned char *md);

#ifdef __cplusplus
};
#endif

#endif /* _SNEFRU_H_ */

