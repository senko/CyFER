/** \file
  * \brief Public-key cryptography support
  */

#ifndef _CYFER_PK_H_
#define _CYFER_PK_H_

#define CYFER_PK_NONE 0
#define CYFER_PK_RSA 1
#define CYFER_PK_ELGAMAL 2
#define CYFER_PK_LUC 3

#ifdef CYFER_INTERNAL
#include <bignum.h>
#include <pkiutil.h>
#include <rsa.h>
#include <elgamal.h>
#include <luc.h>

typedef struct {
	int type;
	union {
		RSA_CTX rsa;
		ELGAMAL_CTX elgamal;
		LUC_CTX luc;
	} u;
} CYFER_PK_CTX;
#else
#include <cyfer/cyfer.h>
//! \brief Public-key algorithm context
typedef void CYFER_PK_CTX;
#endif

//! \brief A structure describing supported public-key algorithms
typedef struct {
	//! \brief Algorithm type
	int type;
	//! \brief Algorithm name
	char *name;
	//! \brief Encryption support
	bool encryption;
	//! \brief Signature support
	bool signature;
} CYFER_Pk_t;

#ifdef __cplusplus
extern "C" {
#endif

//! \brief Returns a list of supported public-key algorithms.
CYFER_API CYFER_Pk_t *CYFER_Pk_Get_Supported(void);

//! \brief Selects public-key algorithm to use.
//! \param name Algorithm name
//! \param enc [output] True if algorithm can be used for encryption
//! \param sig [output] True if algorithm can be used for signatures
//! \returns An integer representing the selected algorithm
CYFER_API int CYFER_Pk_Select(const char *name, bool *enc, bool *sig);

//! \brief Creates and initializes algorithm context.
//! \param type An integer representing algorithm to use
//! \returns An initialized hash context, or NULL in case of error
CYFER_API CYFER_PK_CTX *CYFER_Pk_Init(int type);

//! \brief Generates new public/private key pair.
//! \param ctx Algorithm context
//! \param keylen Key length (in bits)
CYFER_API void CYFER_Pk_Generate_Key(CYFER_PK_CTX *ctx, size_t keylen);

//! \brief Returns plaintext and ciphertext block sizes.
//! \param ctx Algorithm context
//! \param pt_len [output] Length of plaintext block (in bytes)
//! \param ct_len [output] Length of ciphertext block (in bytes)
CYFER_API void CYFER_Pk_Size(CYFER_PK_CTX *ctx, size_t *pt_len, size_t *ct_len);

//! \brief Returns private and public key lengths.
//! \param ctx Algorithm context
//! \param privlen [output] Private key length
//! \param publen [output] Public key length
CYFER_API void CYFER_Pk_KeySize(CYFER_PK_CTX *ctx, size_t *privlen, size_t *publen);

//! \brief Exports private and/or public key.
//! \param ctx Algorithm context
//! \param priv [output] Buffer for private key data
//! \param pub [output] Buffer for public key data
//! \note The keys themselves big integers stored in MPI (multi precision integer) format compatible with PKCS standards.
//! \note It is possible to export one key by providing NULL as the buffer for the other one.
CYFER_API void CYFER_Pk_Export_Key(CYFER_PK_CTX *ctx, unsigned char *priv, unsigned char *pub);

//! \brief Imports private and/or public key.
//! \param ctx Algorithm context
//! \param priv Private key data
//! \param privlen Private key length
//! \param pub Public key data
//! \param publen Public key length
//! \note It is possible to import one key by providing NULL as the data pointer for the other one.
//! \note The keys themselves big integers stored in MPI (multi precision integer) format compatible with PKCS standards.
//! \returns True if the keys are successfully imported, false on error
CYFER_API bool CYFER_Pk_Import_Key(CYFER_PK_CTX *ctx, unsigned char *priv, size_t privlen, unsigned char *pub, size_t publen);

//! \brief Encrypts a block of data.
//! \param ctx Algorithm context
//! \param input Input data block
//! \param output [output] Output data buffer
CYFER_API void CYFER_Pk_Encrypt(CYFER_PK_CTX *ctx, const unsigned char *input, unsigned char *output);

//! \brief Decrypts a block of data.
//! \param ctx Algorithm context
//! \param input Input data block
//! \param output [output] Output data buffer
CYFER_API void CYFER_Pk_Decrypt(CYFER_PK_CTX *ctx, const unsigned char *input, unsigned char *output);

//! \brief Signs a block of data.
//! \param ctx Algorithm context
//! \param input Input data block
//! \param output [output] Signature buffer
CYFER_API void CYFER_Pk_Sign(CYFER_PK_CTX *ctx, const unsigned char *input, unsigned char *output);

//! \brief Verifies signature for a block of data.
//! \param ctx Algorithm context
//! \param signature Signature block to verify
//! \param message Original data block
//! \returns True if the signature matches the data, false otherwise
CYFER_API bool CYFER_Pk_Verify(CYFER_PK_CTX *ctx, const unsigned char *signature, const unsigned char *message);

//! \brief Finalizes the algorithm, destroys and frees the context.
//! \param ctx Algorithm context
CYFER_API void CYFER_Pk_Finish(CYFER_PK_CTX *ctx);

#ifdef __cplusplus
};
#endif

#endif /* _CYFER_PK_H_ */

