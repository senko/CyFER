/** \file
  * \brief Hash (message digest) algorithm support
  */

#ifndef _CYFER_HASH_H_
#define _CYFER_HASH_H_

#define CYFER_HASH_NONE 0
#define CYFER_HASH_MD4 1
#define CYFER_HASH_MD5 2
#define CYFER_HASH_SHA1 3
#define CYFER_HASH_RMD160 4
#define CYFER_HASH_ADLER32 5
#define CYFER_HASH_SNEFRU 6
#define CYFER_HASH_CRC32 7
#define CYFER_HASH_MD2 8
#define CYFER_HASH_SHA256 9

#ifdef CYFER_INTERNAL
#include <md4.h>
#include <md5.h>
#include <sha1.h>
#include <rmd160.h>
#include <adler32.h>
#include <snefru.h>
#include <crc32.h>
#include <md2.h>
#include <sha256.h>

typedef struct {
	int type;
	union {
		MD4_CTX md4;
		MD5_CTX md5;
		SHA1_CTX sha1;
		RMD160_CTX rmd160;
		ADLER32_CTX adler32;
		SNEFRU_CTX snefru;
		CRC32_CTX crc32;
		MD2_CTX md2;
		SHA256_CTX sha256;
	} u;
} CYFER_HASH_CTX;
#else
#include <cyfer/cyfer.h>
//! \brief Hash algorithm context
typedef void CYFER_HASH_CTX;
#endif

//! \brief A structure describing supported hash algorithms
typedef struct {
	//! \brief Algorithm id
	int type;
	//! \brief Algorithm name
	char *name;
	//! \brief Hash value length (in bytes)
	size_t length;
} CYFER_Hash_t;

#ifdef __cplusplus
extern "C" {
#endif 

//! \brief Returns a list of supported hash algorithms.
CYFER_API CYFER_Hash_t *CYFER_Hash_Get_Supported(void);

//! \brief Selects hash algorithm to use
//! \param name Hash algorithm name
//! \param length [output] Length of hash value (in bytes)
//! \returns An integer representing the selected algorithm
CYFER_API int CYFER_Hash_Select(const char *name, size_t *length);

//! \brief Creates and initializes algorithm context
//! \param type An integer representing hash algorithm to use
//! \returns An initialized hash context, or NULL in case of error
CYFER_API CYFER_HASH_CTX *CYFER_Hash_Init(int type);


//! \brief Processes a chunk of data
//! \param ctx Algorithm context
//! \param data Input to the hash algorithm
//! \param len Length of input data (in bytes)
CYFER_API void CYFER_Hash_Update(CYFER_HASH_CTX *ctx, const unsigned char *data, size_t len);

//! \brief Finalizes the algorithm and returns the hash value
//! \note The function also destroys and frees the hash context
//! \param ctx Algorithm context
//! \param md [output] A buffer for hash value (must be big enough to hold the value)
CYFER_API void CYFER_Hash_Finish(CYFER_HASH_CTX *ctx, unsigned char *md);

//! \brief An utility function to calculate hash of one chunk of data
//! \param type An integer representing the hash algorithm to use
//! \param data Input data
//! \param len Input data length (in bytes)
//! \param md [output] A buffer for the resulting hash value (must be big enough to hold the value)
CYFER_API int CYFER_Hash(int type, const unsigned char *data, size_t len, unsigned char *md);

#ifdef __cplusplus
};
#endif 

#endif /* _CYFER_HASH_H_ */

