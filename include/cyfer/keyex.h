/** \file
  * \brief Asymmetric key-exchange support
  */

#ifndef _CYFER_KEYEX_H_
#define _CYFER_KEYEX_H_

#define CYFER_KEYEX_NONE 0
#define CYFER_KEYEX_DH 1

#ifdef CYFER_INTERNAL
#include <dh.h>

typedef struct {
	int type;
	union {
		DH_CTX dh;
	} u;
} CYFER_KEYEX_CTX;
#else
#include <cyfer/cyfer.h>
//! \brief Key-exchange algorithm context
typedef void CYFER_KEYEX_CTX;
#endif

//! \brief A structure describing supported key-exchange algorithms
typedef struct {
	//! \brief Algorithm id
	int type;
	//! \brief Algorithm name
	char *name;
} CYFER_KeyEx_t;

#ifdef __cplusplus
extern "C" {
#endif

//! \brief Returns a list of supported key-exchange algorithms.
CYFER_API CYFER_KeyEx_t *CYFER_KeyEx_Get_Supported(void);

//! \brief Selects key-exchange algorithm to use.
//! \param name Algorithm name
//! \returns An integer representing the selected algorithm
CYFER_API int CYFER_KeyEx_Select(const char *name);

//! \brief Creates and initializes algorithm context.
//! \param type An integer representing algorithm to use
//! \returns An initialized hash context, or NULL in case of error
CYFER_API CYFER_KEYEX_CTX *CYFER_KeyEx_Init(int type);

//! \brief Finalizes the algorithm, destroys and frees the context.
//! \param ctx Algorithm context
CYFER_API void CYFER_KeyEx_Finish(CYFER_KEYEX_CTX *ctx);

//! \brief Generates new public/private key pair.
//! \param ctx Algorithm context
CYFER_API void CYFER_KeyEx_Generate_Key(CYFER_KEYEX_CTX *ctx);

//! \brief Returns private and public key lengths.
//! \param ctx Algorithm context
//! \param privlen [output] Shared key length
//! \param publen [output] Public key length
CYFER_API void CYFER_KeyEx_KeySize(CYFER_KEYEX_CTX *ctx, size_t *privlen, size_t *publen);

//! \brief Computes shared key.
//! \param ctx Algorithm context
//! \param other Other side's public key
//! \param len Other side's public key length
//! \returns True if shared key was successfully computed, false otherwise
CYFER_API bool CYFER_KeyEx_Compute_Key(CYFER_KEYEX_CTX *ctx, unsigned char *other, size_t len);

//! \brief Exports public key.
//! \param ctx Algorithm context
//! \param key [output] Buffer for public key data
CYFER_API void CYFER_KeyEx_Public_Key(CYFER_KEYEX_CTX *ctx, unsigned char *key);

//! \brief Returns shared key.
//! \param ctx Algorithm context
//! \param key [output] Buffer for shared key data
//! \param len Desired length of shared key
//! \note If desired length is smaller than the shared key size, only a part of the key is returned. If it is larger, the key is repeated.
CYFER_API void CYFER_KeyEx_Shared_Key(CYFER_KEYEX_CTX *ctx, unsigned char *key, size_t len);

#ifdef __cplusplus
};
#endif

#endif /* _CYFER_KEYEX_H_ */

