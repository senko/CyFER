#ifndef _CIPHER_MODES_H_
#define _CIPHER_MODES_H_

#ifndef _CIPHER_H_

#define CYFER_MODE_NONE 0
#define CYFER_MODE_ECB 1
#define CYFER_MODE_CBC 2
#define CYFER_MODE_CFB 3
#define CYFER_MODE_OFB 4

#include <util.h>
typedef struct {
	int mode;
	void *context;
	cyfer_crypt_handler_t encrypt;
	cyfer_crypt_handler_t decrypt;
	size_t length;
	unsigned char *chain;
	unsigned char *outbuf;
} CYFER_BLOCK_MODE_CTX;

typedef struct {
	int type;
	char *name;
	size_t length;
} CYFER_BlockMode_t;

CYFER_API CYFER_BlockMode_t *CYFER_BlockCipher_Get_SupportedModes(void);
CYFER_API int CYFER_BlockCipher_SelectMode(const char *name, size_t *length);

#endif

#ifdef __cplusplus
extern "C" {
#endif 


CYFER_API int CYFER_BlockMode_Init(int mode, CYFER_BLOCK_MODE_CTX *ctx, void *cipher_ctx, void *encrypt, void *decrypt, const unsigned char *ivec, size_t length);
CYFER_API void CYFER_BlockMode_Encrypt(CYFER_BLOCK_MODE_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_BlockMode_Decrypt(CYFER_BLOCK_MODE_CTX *ctx, const unsigned char *input, unsigned char *output);
CYFER_API void CYFER_BlockMode_Finish(CYFER_BLOCK_MODE_CTX *ctx);

#ifdef __cplusplus
};
#endif 

#endif /* _CIPHER_MODES_H_ */

