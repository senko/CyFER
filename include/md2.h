#ifndef _MD2_H_
#define _MD2_H_

#include <util.h>

typedef struct {
	u8 *csum;
	u8 *x;
	u8 *buffer;
	size_t buflen;
} MD2_CTX;

#ifdef __cplusplus
extern "C" {
#endif
	
CYFER_API void CYFER_MD2_Init(MD2_CTX *ctx);
CYFER_API void CYFER_MD2_Update(MD2_CTX *ctx, const unsigned char *data, size_t len);
CYFER_API void CYFER_MD2_Finish(MD2_CTX *ctx, unsigned char *md);
CYFER_API void CYFER_MD2(const unsigned char *data, size_t len, unsigned char *md);

#ifdef __cplusplus
};
#endif

#endif /* _MD2_H_ */

