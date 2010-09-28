#ifndef _DH_H_
#define _DH_H_

#include <bignum.h>

typedef struct {
	bignum_t p;
	bignum_t g;
	bignum_t priv_key;
	bignum_t pub_key;
	bignum_t shared_key;
} DH_CTX;

#ifdef __cplusplus
extern "C" {
#endif
	
CYFER_API void CYFER_DH_Init(DH_CTX *ctx);
CYFER_API void CYFER_DH_Finish(DH_CTX *ctx);
CYFER_API void CYFER_DH_Generate_Key(DH_CTX *ctx);
CYFER_API void CYFER_DH_KeySize(DH_CTX *ctx, size_t *privlen, size_t *publen);
CYFER_API bool CYFER_DH_Compute_Key(DH_CTX *ctx, unsigned char *other, size_t len);
CYFER_API void CYFER_DH_Public_Key(DH_CTX *ctx, unsigned char *key);
CYFER_API void CYFER_DH_Shared_Key(DH_CTX *ctx, unsigned char *key, size_t len);

#ifdef __cplusplus
};
#endif

#endif /* _DH_H_ */

