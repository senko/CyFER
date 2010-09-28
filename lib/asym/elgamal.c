#include <stdlib.h>
#include <string.h>
#include <util.h>
#include <elgamal.h>
#include <pkiutil.h>

#define Size(ctx) bignum_bytes_needed(ctx->p)

/* implementation */

static void generate_key(ELGAMAL_CTX *ctx, size_t keylen)
{
	bignum_random_bits(ctx->p, ctx->state, keylen);
	bignum_nextprime(ctx->p, ctx->p);

	bignum_random_max(ctx->g, ctx->state, ctx->p);
	bignum_random_max(ctx->x, ctx->state, ctx->p);

	bignum_powm(ctx->y, ctx->g, ctx->x, ctx->p);
}

static void encrypt_block(ELGAMAL_CTX *ctx, unsigned char *dest, const unsigned char *src)
{
	bignum_t m, k, a, b;

	bignum_init(m); bignum_init(k); bignum_init(a); bignum_init(b);
	mpi_raw_load(m, src, Size(ctx) - 1);

	bignum_sub_u32(a, ctx->p, 1);
	bignum_relprime(k, a, ctx->p, ctx->state);

	bignum_powm(a, ctx->g, k, ctx->p);
	bignum_powm(b, ctx->y, k, ctx->p);
	bignum_mul(b, b, m);
	bignum_mod(b, b, ctx->p);

	mpi_raw_store(a, dest, Size(ctx));
	mpi_raw_store(b, dest + Size(ctx), Size(ctx));

	bignum_free(m); bignum_free(k); bignum_free(a); bignum_free(b);
}

static void decrypt_block(ELGAMAL_CTX *ctx, unsigned char *dest, const unsigned char *src)
{
	bignum_t m, k, a, b;

	bignum_init(m); bignum_init(k); bignum_init(a); bignum_init(b);
	mpi_raw_load(a, src, Size(ctx));
	mpi_raw_load(b, src + Size(ctx), Size(ctx));

	bignum_powm(a, a, ctx->x, ctx->p);
	bignum_invert(m, a, ctx->p);
	bignum_mul(m, m, b);
	bignum_mod(m, m, ctx->p);

	mpi_raw_store(m, dest, Size(ctx) - 1);
	bignum_free(m); bignum_free(k); bignum_free(a); bignum_free(b);
}

static void sign_block(ELGAMAL_CTX *ctx, unsigned char *dest, const unsigned char *src)
{
	bignum_t m, k, a, b, t;

	bignum_init(m); bignum_init(k); bignum_init(a); bignum_init(b); bignum_init(t);
	mpi_raw_load(m, src, Size(ctx) - 1);

	bignum_sub_u32(t, ctx->p, 1);
	bignum_relprime(k, t, ctx->p, ctx->state);

	bignum_powm(a, ctx->g, k, ctx->p);
	bignum_mul(b, ctx->x, a);

	if (bignum_cmp(m, b) < 0) bignum_add(m, m, t);
	bignum_sub(m, m, b);

	/*
	bignum_sub(m, m, b);
	if (bignum_sgn(m) < 0) bignum_add(m, m, t);
	*/

	bignum_invert(k, k, t);
	bignum_mul(b, m, k);
	bignum_mod(b, b, t);

	mpi_raw_store(a, dest, Size(ctx));
	mpi_raw_store(b, dest + Size(ctx), Size(ctx));

	bignum_free(m); bignum_free(k); bignum_free(a); bignum_free(b); bignum_free(t);
}

static bool sign_verify(ELGAMAL_CTX *ctx, const unsigned char *dest, const unsigned char *src)
{
	bignum_t m, k, a, b, t1, t2;
	bool retval;

	bignum_init(m); bignum_init(k); bignum_init(a); bignum_init(b); bignum_init(t1); bignum_init(t2);
	mpi_raw_load(a, src, Size(ctx));
	mpi_raw_load(b, src + Size(ctx), Size(ctx));
	mpi_raw_load(m, dest, Size(ctx) - 1);

	bignum_powm(k, ctx->y, a, ctx->p);
	bignum_powm(t2, a, b, ctx->p);
	bignum_mul(t1, k, t2);
	bignum_mod(t1, t1, ctx->p);

	bignum_powm(t2, ctx->g, m, ctx->p);
	retval = (bool) !bignum_cmp(t1, t2);

	bignum_free(m); bignum_free(k); bignum_free(a); bignum_free(b); bignum_free(t1); bignum_free(t2);
	return retval;
}


/* interface */

void CYFER_ELGAMAL_Init(ELGAMAL_CTX *ctx)
{
	bignum_random_init(ctx->state, rand());
	bignum_init(ctx->p); bignum_init(ctx->g);
	bignum_init(ctx->x); bignum_init(ctx->y);
	ctx->publen = ctx->privlen = 0;
}

void CYFER_ELGAMAL_Finish(ELGAMAL_CTX *ctx)
{
	bignum_free(ctx->p); bignum_free(ctx->g);
	bignum_free(ctx->x); bignum_free(ctx->y);
	bignum_random_free(ctx->state);
}

void CYFER_ELGAMAL_Generate_Key(ELGAMAL_CTX *ctx, size_t keylen)
{
	generate_key(ctx, keylen);
	ctx->privlen = 6 + bignum_bytes_needed(ctx->x) + bignum_bytes_needed(ctx->g) + bignum_bytes_needed(ctx->p);
	ctx->publen = 6 + bignum_bytes_needed(ctx->y) + bignum_bytes_needed(ctx->g) + bignum_bytes_needed(ctx->p);
}

void CYFER_ELGAMAL_Size(ELGAMAL_CTX *ctx, size_t *pt_len, size_t *ct_len)
{
	if (pt_len) *pt_len = Size(ctx) - 1;
	if (ct_len) *ct_len = 2 * Size(ctx);
}

void CYFER_ELGAMAL_KeySize(ELGAMAL_CTX *ctx, size_t *privlen, size_t *publen)
{
	if (privlen) *privlen = ctx->privlen;
	if (publen) *publen = ctx->publen;
}

void CYFER_ELGAMAL_Export_Key(ELGAMAL_CTX *ctx, unsigned char *priv, unsigned char *pub)
{
	if (priv) mpi_store(priv, 3, &(ctx->x), &(ctx->g), &(ctx->p));
	if (pub) mpi_store(pub, 3, &(ctx->y), &(ctx->g), &(ctx->p));
}

bool CYFER_ELGAMAL_Import_Key(ELGAMAL_CTX *ctx, unsigned char *priv, size_t privlen, unsigned char *pub, size_t publen)
{
	if (priv) if (!mpi_load(priv, privlen, 3, &(ctx->x), &(ctx->g), &(ctx->p))) return false;
	if (pub) if (!mpi_load(pub, publen, 3, &(ctx->y), &(ctx->g), &(ctx->p))) return false;
	ctx->privlen = 6 + bignum_bytes_needed(ctx->x) + bignum_bytes_needed(ctx->g) + bignum_bytes_needed(ctx->p);
	ctx->publen = 6 + bignum_bytes_needed(ctx->y) + bignum_bytes_needed(ctx->g) + bignum_bytes_needed(ctx->p);
	return true;
}

void CYFER_ELGAMAL_Encrypt(ELGAMAL_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	encrypt_block(ctx, output, input);
}

void CYFER_ELGAMAL_Decrypt(ELGAMAL_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	decrypt_block(ctx, output, input);
}

void CYFER_ELGAMAL_Sign(ELGAMAL_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	sign_block(ctx, output, input);
}

bool CYFER_ELGAMAL_Verify(ELGAMAL_CTX *ctx, const unsigned char *signature, const unsigned char *message)
{
	return sign_verify(ctx, message, signature);
}

