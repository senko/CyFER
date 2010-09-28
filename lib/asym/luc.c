#include <stdlib.h>
#include <string.h>
#include <luc.h>
#include <assert.h>
#include <pkiutil.h>

#define Size(ctx) bignum_bytes_needed(ctx->n)

/* implementation */

static void generate_key(LUC_CTX *ctx, size_t keylen)
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
		bignum_sub_u32(p, p, 1); bignum_sub_u32(q, q, 1);
		bignum_lcm(t, p, q);
		bignum_add_u32(p, p, 2); bignum_add_u32(q, q, 2);
		bignum_lcm(z, p, q);
		bignum_lcm(t, t, z);

		bignum_relprime(ctx->e, ctx->n, t, state);
		if (bignum_invert(ctx->d, ctx->e, t)) break;
	}

	bignum_random_free(state);
	bignum_free(p); bignum_free(q); bignum_free(t); bignum_free(z);
}

static unsigned char *to_binary(bignum_t num, size_t *len)
{
	unsigned char *tmp;
	size_t l;
	bignum_t x,  y;

	bignum_init(x);
	bignum_init_set(y, num);

	l = bignum_bits_needed(y);
	*len = l;
	tmp = malloc(l);

	while (bignum_cmp_u32(y, 0)) {
		l--;
		bignum_mod_u32(x, y, 2);
		if (bignum_cmp_u32(x, 0)) tmp[l] = 1; else tmp[l] = 0;
		bignum_div_u32(y, y, 2);
	}

	bignum_free(x); bignum_free(y);
	return tmp;
}

static void engine(unsigned char *dest, const unsigned char *src, bignum_t key, bignum_t n, size_t size, int nail)
{
	size_t i, blen;
	unsigned char *bin;
	bignum_t v, p, oldv, r, s, t1, t2;

	bignum_init(p);
	mpi_raw_load(p, src, size - nail);

	bin = to_binary(key, &blen);

	bignum_init(r); bignum_init(s); bignum_init(t1); bignum_init(t2);
	bignum_init_set(v, p);
	bignum_init_set_u32(oldv, 2);

	bignum_div_u32(key, key, 2);
	for (i = 1; i < blen; i++) {
		bignum_mul(r, v, oldv); bignum_sub(r, r, p); bignum_mod(r, r, n);
		bignum_mul(s, v, v); bignum_sub_u32(s, s, 2); bignum_mod(s, s, n);

		bignum_mul(t1, p, v); bignum_mul(t1, t1, v);
		bignum_mul(t2, v, oldv);
		bignum_sub(t1, t1, t2); bignum_sub(t1, t1, p);
		bignum_mod(t1, t1, n);

		bignum_mod_u32(t2, key, 2);
		if (bin[i]) {
			bignum_set(v, t1);
			bignum_set(oldv, s);
		} else {
			bignum_set(v, s);
			bignum_set(oldv, r);
		}
		bignum_div_u32(key, key, 2);
	}

	mpi_raw_store(v, dest, size - 1 + nail);

	bignum_free(r); bignum_free(s); bignum_free(t1); bignum_free(t2);
	bignum_free(v); bignum_free(oldv); bignum_free(p); free(bin);
}

/* interface */

void CYFER_LUC_Init(LUC_CTX *ctx)
{
	bignum_init(ctx->e); bignum_init(ctx->d); bignum_init(ctx->n);
	ctx->publen = ctx->privlen = 0;
}

void CYFER_LUC_Finish(LUC_CTX *ctx)
{
	bignum_free(ctx->e); bignum_free(ctx->d); bignum_free(ctx->n);
}

void CYFER_LUC_Generate_Key(LUC_CTX *ctx, size_t keylen)
{
	generate_key(ctx, keylen);
	ctx->publen = 4 + bignum_bytes_needed(ctx->n) + bignum_bytes_needed(ctx->e);
	ctx->privlen = 4 + bignum_bytes_needed(ctx->n) + bignum_bytes_needed(ctx->d);
}

void CYFER_LUC_Size(LUC_CTX *ctx, size_t *pt_len, size_t *ct_len)
{
	if (pt_len) *pt_len = Size(ctx) - 1;
	if (ct_len) *ct_len = Size(ctx);
}

void CYFER_LUC_KeySize(LUC_CTX *ctx, size_t *privlen, size_t *publen)
{
	if (privlen) *privlen = ctx->privlen;
	if (publen) *publen = ctx->publen;
}

void CYFER_LUC_Export_Key(LUC_CTX *ctx, unsigned char *priv, unsigned char *pub)
{
	if (priv) mpi_store(priv, 2, &(ctx->n), &(ctx->d));
	if (pub) mpi_store(pub, 2, &(ctx->n), &(ctx->e));
}

bool CYFER_LUC_Import_Key(LUC_CTX *ctx, unsigned char *priv, size_t privlen, unsigned char *pub, size_t publen)
{
	if (priv) if (!mpi_load(priv, privlen, 2, &(ctx->n), &(ctx->d))) return false;
	if (pub) if (!mpi_load(pub, publen, 2, (&ctx->n), &(ctx->e))) return false;
	ctx->publen = 4 + bignum_bytes_needed(ctx->n) + bignum_bytes_needed(ctx->e);
	ctx->privlen = 4 + bignum_bytes_needed(ctx->n) + bignum_bytes_needed(ctx->d);
	return true;
}

void CYFER_LUC_Encrypt(LUC_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	engine(output, input, ctx->e, ctx->n, Size(ctx), 1);
}

void CYFER_LUC_Decrypt(LUC_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	engine(output, input, ctx->d, ctx->n, Size(ctx), 0);
}

void CYFER_LUC_Sign(LUC_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	engine(output, input, ctx->d, ctx->n, Size(ctx), 1);
}

bool CYFER_LUC_Verify(LUC_CTX *ctx, const unsigned char *signature, const unsigned char *message)
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
