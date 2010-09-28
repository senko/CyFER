#include <stdlib.h>
#include <string.h>
#include <util.h>
#include <rsa.h>
#include <pkiutil.h>

#define Size(ctx) bignum_bytes_needed(ctx->n)

/* implementation */

static void generate_key(RSA_CTX *ctx, size_t keylen)
{
	randstate_t state;
	bignum_t p, q, t, z;

	keylen /= 2;

	bignum_random_init(state, rand());
	bignum_init(p); bignum_init(q); bignum_init(t); bignum_init(z);

	while (1) {
		bignum_random_bits(p, state, keylen);
		bignum_nextprime(p, p);

		bignum_random_bits(q, state, keylen);
		bignum_nextprime(q, q);

		bignum_mul(ctx->n, p, q);
		bignum_sub_u32(p, p, 1);
		bignum_sub_u32(q, q, 1);
		bignum_mul(z, p, q);

		bignum_relprime(ctx->e, p, z, state);
		if (bignum_invert(ctx->d, ctx->e, z)) break;
	}

	bignum_free(p); bignum_free(q); bignum_free(t); bignum_free(z);
	bignum_random_free(state); 
}

static void engine(unsigned char *dest, const unsigned char *src, bignum_t x, bignum_t y, size_t size, int nail)
{
	bignum_t ciphertext, plaintext;

	bignum_init(ciphertext); bignum_init(plaintext);

	mpi_raw_load(plaintext, src, size - nail);
	bignum_powm(ciphertext, plaintext, x, y);
	mpi_raw_store(ciphertext, dest, size - 1 + nail);

	bignum_free(ciphertext); bignum_free(plaintext);
}

/* interface */

void CYFER_RSA_Init(RSA_CTX *ctx)
{
	bignum_init(ctx->e); bignum_init(ctx->d); bignum_init(ctx->n);
	ctx->publen = ctx->privlen = 0;
}

void CYFER_RSA_Finish(RSA_CTX *ctx)
{
	bignum_free(ctx->e); bignum_free(ctx->d); bignum_free(ctx->n);
}

void CYFER_RSA_Generate_Key(RSA_CTX *ctx, size_t keylen)
{
	generate_key(ctx, keylen);
	ctx->publen = 4 + bignum_bytes_needed(ctx->n) + bignum_bytes_needed(ctx->e);
	ctx->privlen = 4 + bignum_bytes_needed(ctx->n) + bignum_bytes_needed(ctx->d);
}

void CYFER_RSA_Size(RSA_CTX *ctx, size_t *pt_len, size_t *ct_len)
{
	if (pt_len) *pt_len = Size(ctx) - 1;
	if (ct_len) *ct_len = Size(ctx);
}

void CYFER_RSA_KeySize(RSA_CTX *ctx, size_t *privlen, size_t *publen)
{
	if (privlen) *privlen = ctx->privlen;
	if (publen) *publen = ctx->publen;
}

void CYFER_RSA_Export_Key(RSA_CTX *ctx, unsigned char *priv, unsigned char *pub)
{
	if (priv) mpi_store(priv, 2, &(ctx->n), &(ctx->d));
	if (pub) mpi_store(pub, 2, &(ctx->n), &(ctx->e));
}

bool CYFER_RSA_Import_Key(RSA_CTX *ctx, unsigned char *priv, size_t privlen, unsigned char *pub, size_t publen)
{
	if (priv) if (!mpi_load(priv, privlen, 2, &(ctx->n), &(ctx->d))) return false;
	if (pub) if (!mpi_load(pub, publen, 2, (&ctx->n), &(ctx->e))) return false;

	ctx->publen = 4 + bignum_bytes_needed(ctx->n) + bignum_bytes_needed(ctx->e);
	ctx->privlen = 4 + bignum_bytes_needed(ctx->n) + bignum_bytes_needed(ctx->d);
	return true;
}

void CYFER_RSA_Encrypt(RSA_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	engine(output, input, ctx->e, ctx->n, Size(ctx), 1);
}

void CYFER_RSA_Decrypt(RSA_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	engine(output, input, ctx->d, ctx->n, Size(ctx), 0);
}

void CYFER_RSA_Sign(RSA_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	engine(output, input, ctx->d, ctx->n, Size(ctx), 1);
}

bool CYFER_RSA_Verify(RSA_CTX *ctx, const unsigned char *signature, const unsigned char *message)
{
	unsigned char *tmp;

	tmp = malloc(Size(ctx) - 1);
	engine(tmp, signature, ctx->e, ctx->n, Size(ctx), 0);

	if (memcmp(tmp, message, Size(ctx) - 1)) {
		free(tmp);
		return 0;
	}
	free(tmp);
	return 1;
}

