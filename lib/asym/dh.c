#include <stdlib.h>
#include <string.h>
#include <util.h>
#include <dh.h>
#include <pkiutil.h>

/* constants */

#define DH_G "0x2344010023498019329fafef32324ff65f22398490001291209291"
#define DH_P "0x0113f7fefd73f9d36ff3fefd2e34102202d01022d0c4410113f7fefc1400000014000003e3f3fefd43fbfefc12cc102062cc102063f7fefecc300d0013"

/* implementation */

static void generate_key(DH_CTX *ctx)
{
	randstate_t state;

	bignum_random_init(state, rand());
	bignum_random_max(ctx->priv_key, state, ctx->p);
	bignum_powm(ctx->pub_key, ctx->g, ctx->priv_key, ctx->p);
	bignum_random_free(state);
}

static inline void compute_key(DH_CTX *ctx, bignum_t other, bignum_t result)
{
	bignum_powm(result, other, ctx->priv_key, ctx->p);
}

/* interface */

void CYFER_DH_Init(DH_CTX *ctx)
{
	bignum_init(ctx->p); bignum_init(ctx->g);
	bignum_init(ctx->pub_key); bignum_init(ctx->priv_key);
	bignum_init(ctx->shared_key);
	bignum_set_str(ctx->p, DH_P, 0);
	bignum_set_str(ctx->g, DH_G, 0);
}

void CYFER_DH_Finish(DH_CTX *ctx)
{
	bignum_free(ctx->p); bignum_free(ctx->g);
	bignum_free(ctx->pub_key); bignum_free(ctx->priv_key);
	bignum_free(ctx->shared_key);
}

void CYFER_DH_Generate_Key(DH_CTX *ctx)
{
	generate_key(ctx);
}

void CYFER_DH_KeySize(DH_CTX *ctx, size_t *privlen, size_t *publen)
{
	if (privlen) *privlen = bignum_bytes_needed(ctx->shared_key);
	if (publen) *publen = 2 + bignum_bytes_needed(ctx->pub_key);
}

bool CYFER_DH_Compute_Key(DH_CTX *ctx, unsigned char *other, size_t len)
{
	bignum_t x;
	bignum_init(x);

	if (!mpi_load(other, len, 1, &x)) {
		bignum_free(x); return false;
	}
	compute_key(ctx, x, ctx->shared_key);
	bignum_free(x);
	return true;
}

void CYFER_DH_Public_Key(DH_CTX *ctx, unsigned char *key)
{
	mpi_store(key, 1, &(ctx->pub_key));
}

void CYFER_DH_Shared_Key(DH_CTX *ctx, unsigned char *key, size_t len)
{
	unsigned char *a;
	size_t alen, i;
	
	alen = bignum_bytes_needed(ctx->shared_key);

	a = malloc(alen);

	mpi_raw_store(ctx->shared_key, a, alen);
	for (i = 0; i < len; i++) key[i] = a[i % alen];
	
	free(a);
}

