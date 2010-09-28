#include <stdlib.h>
#include <string.h>
#include <md2.h>


/* constants and transformations */

static const u8 s[256] = {
	41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
	19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
	76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
	138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
	245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
	148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
	39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
	181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
	150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
	112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
	96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
	85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
	234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
	129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
	8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
	203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
	166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
	31, 26, 219, 153, 141, 51, 159, 17, 131, 20
};

/* implementation */

static void md2_compress_block(MD2_CTX *ctx, bool last)
{
	u8 t;
	int j, k;
	size_t len = ctx->buflen;
	u8 *source = ctx->buffer;

	if (last) {
		k = 16 - (int) len; if (!k) k = 16;
		for (j = 0; j < k; j++) source[len++] = (u8) k;
	}
	len /= 16;

	while (len) {
		for (j = 0; j < 16; j++) {
			ctx->x[j + 16] = source[j];
			ctx->x[j + 32] = ctx->x[j + 16] ^ ctx->x[j];
		}
		t = 0;
		for (j = 0; j < 18; j++) {
			for (k = 0; k < 48; k++) ctx->x[k] = t = ctx->x[k] ^ s[t];
			t = (t + (u8) j) % 256;
		}
		t = ctx->csum[15];
		for (j = 0; j < 16; j++) t = ctx->csum[j] ^= s[source[j] ^ t];
		len--;
	}
}

/* interface */

void CYFER_MD2_Init(MD2_CTX *ctx)
{
	ctx->buffer = malloc(2 * 16);
	ctx->x = malloc(48);
	ctx->csum = malloc(16);
	memset(ctx->x, 0, 48); memset(ctx->csum, 0, 16);
	ctx->buflen = 0;
}

void CYFER_MD2_Finish(MD2_CTX *ctx, unsigned char *md)
{
	md2_compress_block(ctx, true);
	memcpy(ctx->buffer, ctx->csum, 16);
	ctx->buflen = 16;
	md2_compress_block(ctx, false);
	memcpy(md, ctx->x, 16);
	free(ctx->buffer); ctx->buffer = NULL;
	free(ctx->csum); ctx->csum = NULL;
	free(ctx->x); ctx->x =  NULL;
}

void CYFER_MD2_Update(MD2_CTX *ctx, const unsigned char *data, size_t len)
{
	while (len--) {
		ctx->buffer[ctx->buflen++] = *data++;
		if (ctx->buflen == 16) {
			md2_compress_block(ctx, false);
			ctx->buflen = 0;
		}
	}
}

void CYFER_MD2(const unsigned char *data, size_t len, unsigned char *md)
{
	MD2_CTX ctx;

	CYFER_MD2_Init(&ctx);
	CYFER_MD2_Update(&ctx, data, len);
	CYFER_MD2_Finish(&ctx, md);
}


