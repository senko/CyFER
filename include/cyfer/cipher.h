/** \file
  * \brief Symmetric cipher support
  */

#ifndef _CIPHER_H_
#define _CIPHER_H_

#define CYFER_CIPHER_NONE 0
#define CYFER_CIPHER_BLOWFISH 1
#define CYFER_CIPHER_DES 2
#define CYFER_CIPHER_DESX 3
#define CYFER_CIPHER_TRIPLEDES 4
#define CYFER_CIPHER_RC2 5
#define CYFER_CIPHER_RC4 6
#define CYFER_CIPHER_RC5 7
#define CYFER_CIPHER_RC6 8
#define CYFER_CIPHER_IDEA 9
#define CYFER_CIPHER_AES 10
#define CYFER_CIPHER_DEAL 11
#define CYFER_CIPHER_THREEWAY 12

#define CYFER_MODE_NONE 0
#define CYFER_MODE_ECB 1
#define CYFER_MODE_CBC 2
#define CYFER_MODE_CFB 3
#define CYFER_MODE_OFB 4


#ifdef CYFER_INTERNAL
#include <util.h>
#include <blowfish.h>
#include <des.h>
#include <desx.h>
#include <tripledes.h>
#include <rc2.h>
#include <rc4.h>
#include <rc5.h>
#include <rc6.h>
#include <idea.h>
#include <aes.h>
#include <deal.h>
#include <threeway.h>

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
	union {
		BLOWFISH_CTX blowfish;
		DES_CTX des;
		DESX_CTX desx;
		TRIPLEDES_CTX tripledes;
		RC2_CTX rc2;
		RC5_CTX rc5;
		RC6_CTX rc6;
		IDEA_CTX idea;
		AES_CTX aes;
		DEAL_CTX deal;
		THREEWAY_CTX threeway;
	} u;
	CYFER_BLOCK_MODE_CTX mctx;
} CYFER_BLOCK_CIPHER_CTX;

typedef struct {
	int type;
	union {
		RC4_CTX rc4;
	} u;
} CYFER_STREAM_CIPHER_CTX;

#else
#include <cyfer/cyfer.h>
//! \brief Block cipher algorithm context
typedef void CYFER_BLOCK_CIPHER_CTX;
//! \brief Stream cipher algorithm context
typedef void CYFER_STREAM_CIPHER_CTX;
#endif

//! \brief A structure describing supported block ciphers
typedef struct {
	//! \brief Algorithm id
	int type;
	//! \brief Algorithm name
	char *name;
	//! \brief Key length (maximum key length) in bytes
	size_t keylen;
	//! \brief Minimum key length in bytes
	size_t minkey;
	//! \brief Data block length in bytes
	size_t length;
} CYFER_BlockCipher_t;

//! \brief A structure describing supported stream ciphers
typedef struct {
	//! \brief Algorithm id
	int type;
	//! \brief Algorithm name
	char *name;
	//! \brief Key length (maximum key length) in bytes
	size_t keylen;
	//! \brief Minimum key length in bytes
	size_t minkey;
} CYFER_StreamCipher_t;

//! \brief A structure describing supported block modes of operation
typedef struct {
	//! \brief Mode of operation id
	int type;
	//! \brief Name of mode of operation
	char *name;
	//! \brief Data block length in bytes (0 if it doesn't override underlying algorithm's block size)
	size_t length;
} CYFER_BlockMode_t;


#ifdef __cplusplus
extern "C" {
#endif

//! \brief Returns a list of supported block cipher modes of operation
CYFER_API CYFER_BlockMode_t *CYFER_BlockCipher_Get_SupportedModes(void);

//! \brief Returns a list of supported block ciphers
CYFER_API CYFER_BlockCipher_t *CYFER_BlockCipher_Get_Supported(void);

//! \brief Selects block cipher to use
//! \param name Block cipher name
//! \param keylen [output] Key length (or maximum key length)
//! \param minkey [output] Minimum key length
//! \param length [output] Data block length
//! \note If some output value is not wanted, NULL can be specified as buffer
//! \returns An integer representing the selected algorithm
CYFER_API int CYFER_BlockCipher_Select(const char *name, size_t *keylen, size_t *minkey, size_t *length);

//! \brief Selects block cipher mode of operation to use
//! \param name Block cipher mode name
//! \param length [output] Data block length
//! \note If the data block length is identical to the data block length of the underlying algorithm, the value returned is 0.
//! \note If some output value is not wanted, NULL can be specified as buffer
//! \returns An integer representing the selected block cipher mode
CYFER_API int CYFER_BlockCipher_SelectMode(const char *name, size_t *length);

//! \brief Creates and initializes algorithm context
//! \param type An integer representing block cipher to use
//! \param key Key to use for encryption/decryption
//! \param keylen Key length in bytes
//! \param mode An integer representing block cipher mode to use
//! \param ivec Block cipher mode initialization vector
//! \note If the provided key is shorter than required by the algorithm, it is padded with zeroes.
//! \note If the initialization vector pointer is NULL, the default vector (filled with zeroes) is used.
//! \returns An initialized block cipher context, or NULL in case of error
CYFER_API CYFER_BLOCK_CIPHER_CTX *CYFER_BlockCipher_Init(int type, const unsigned char *key, size_t keylen, int mode, const unsigned char *ivec);

//! \brief Encrypts a block of data.
//! \param ctx Algorithm context
//! \param input Input data block
//! \param output [output] Output data buffer
CYFER_API void CYFER_BlockCipher_Encrypt(CYFER_BLOCK_CIPHER_CTX *ctx, const unsigned char *input, unsigned char *output);

//! \brief Decrypts a block of data.
//! \param ctx Algorithm context
//! \param input Input data block
//! \param output [output] Output data buffer
CYFER_API void CYFER_BlockCipher_Decrypt(CYFER_BLOCK_CIPHER_CTX *ctx, const unsigned char *input, unsigned char *output);

//! \brief Finalizes the algorithm, destroys and frees the context.
//! \param ctx Algorithm context
CYFER_API void CYFER_BlockCipher_Finish(CYFER_BLOCK_CIPHER_CTX *ctx);

//! \brief Returns a list of supported stream ciphers
CYFER_API CYFER_StreamCipher_t *CYFER_StreamCipher_Get_Supported(void);

//! \brief Selects stream cipher to use
//! \param name Stream cipher name
//! \param keylen [output] Key length (or maximum key length)
//! \param minkey [output] Minimum key length
//! \note If some output value is not wanted, NULL can be specified as buffer
//! \returns An integer representing the selected algorithm
CYFER_API int CYFER_StreamCipher_Select(const char *name, size_t *keylen, size_t *minkey);

//! \brief Creates and initializes algorithm context
//! \param type An integer representing stream cipher to use
//! \param key Key to use for encryption/decryption
//! \param keylen Key length in bytes
//! \returns An initialized stream cipher context, or NULL in case of error
CYFER_API CYFER_STREAM_CIPHER_CTX *CYFER_StreamCipher_Init(int type, const unsigned char *key, size_t keylen);

//! \brief Encrypts a block of data.
//! \param ctx Algorithm context
//! \param input Input data block
//! \param output [output] Output data buffer
//! \param length Length of data block
CYFER_API void CYFER_StreamCipher_Encrypt(CYFER_STREAM_CIPHER_CTX *ctx, const unsigned char *input, unsigned char *output, size_t length);

//! \brief Decrypts a block of data.
//! \param ctx Algorithm context
//! \param input Input data block
//! \param output [output] Output data buffer
//! \param length Length of data block
CYFER_API void CYFER_StreamCipher_Decrypt(CYFER_STREAM_CIPHER_CTX *ctx, const unsigned char *input, unsigned char *output, size_t length);

//! \brief Finalizes the algorithm, destroys and frees the context.
//! \param ctx Algorithm context
CYFER_API void CYFER_StreamCipher_Finish(CYFER_STREAM_CIPHER_CTX *ctx);

#ifdef __cplusplus
};
#endif 

#endif /* _CIPHER_H_ */

