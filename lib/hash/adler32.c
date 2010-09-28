#include <stdlib.h>
#include <string.h>
#include <adler32.h>


/* constants and transformations */

static const u32 iv1 = 0x1;
static const u32 iv2 = 0x0;

/* implementation */

static void adler32_compress_block(ADLER32_CTX *ctx, u8 *msg, size_t len)
{
	while (len--) {
		ctx->s1 = (ctx->s1 + (u32) *msg++) % 65521;
		ctx->s2 = (ctx->s2 + ctx->s1) % 65521;
	}
}

/* interface */

void CYFER_ADLER32_Init(ADLER32_CTX *ctx)
{
	ctx->s1 = iv1; ctx->s2 = iv2;
}

void CYFER_ADLER32_Finish(ADLER32_CTX *ctx, unsigned char *md)
{
	u32 val;

	val = (ctx->s2 * 65536) + ctx->s1;
	big_store32(val, md);
}

void CYFER_ADLER32_Update(ADLER32_CTX *ctx, const unsigned char *data, size_t len)
{
	adler32_compress_block(ctx, (u8 *) data, len);
}

void CYFER_ADLER32(const unsigned char *data, size_t len, unsigned char *md)
{
	ADLER32_CTX ctx;

	CYFER_ADLER32_Init(&ctx);
	CYFER_ADLER32_Update(&ctx, data, len);
	CYFER_ADLER32_Finish(&ctx, md);
}

