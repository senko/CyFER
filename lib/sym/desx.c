#include <stdlib.h>
#include <string.h>
#include <desx.h>


/* constants and transformations */

static const u8 desxtable[256] = {
	189, 86, 234, 242, 162, 241, 172, 42, 176, 147, 209, 156, 27, 51, 253, 208,
	48, 4, 182, 220, 125, 223, 50, 75, 247, 203, 69, 155, 49, 187, 33, 90,
	65, 159, 225, 217, 74, 77, 158, 218, 160, 104, 44, 195, 39, 95, 128, 54,
	62, 238, 251, 149, 26, 254, 206, 168, 52, 169, 19, 240, 166, 63, 216, 12,
	120, 36, 175, 35, 82, 193, 103, 23, 245, 102, 144, 231, 232, 7, 184, 96,
	72, 230, 30, 83, 243, 146, 164, 114, 140, 8, 21, 110, 134, 0, 132, 250,
	244, 127, 138, 66, 25, 246, 219, 205, 20, 141, 80, 18, 186, 60, 6, 78,
	236, 179, 53, 17, 161, 136, 142, 43, 148, 153, 183, 113, 116, 211, 228, 191,
	58, 222, 150, 14, 188, 10, 237, 119, 252, 55, 107, 3, 121, 137, 98, 198,
	215, 192, 210, 124, 106, 139, 34, 163, 91, 5, 93, 2, 117, 213, 97, 227,
	24, 143, 85, 81, 173, 31, 11, 94, 133, 229, 194, 87, 99, 202, 61, 108,
	180, 197, 204, 112, 178, 145, 89, 13, 71, 32, 200, 79, 88, 224, 1, 226,
	22, 56, 196, 111, 59, 15, 101, 70, 190, 126, 45, 123, 130, 249, 64, 181,
	29, 115, 248, 235, 38, 199, 135, 151, 37, 84, 177, 40, 170, 152, 157, 165,
	100, 109, 122, 212, 16, 129, 68, 239, 73, 214, 174, 46, 221, 118, 92, 47,
	167, 28, 201, 9, 105, 154, 131, 207, 41, 57, 185, 233, 76, 255, 67, 171
};

/* interface */

void CYFER_DESX_Init(DESX_CTX *ctx, const unsigned char *key)
{
	CYFER_DES_Init(&(ctx->des), key + 8);
	memcpy(ctx->prewhitening, key, 8);
	memcpy(ctx->postwhitening, key + 16, 8);
}

void CYFER_DESX_Finish(DESX_CTX *ctx)
{
	CYFER_DES_Finish(&(ctx->des));
}

void CYFER_DESX_Encrypt(DESX_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	int i;
	unsigned char tmp[8];

	for (i = 0; i < 8; i++) tmp[i] = input[i] ^ ctx->prewhitening[i];
	CYFER_DES_Encrypt(&(ctx->des), tmp, output);
	for (i = 0; i < 8; i++) output[i] ^= ctx->postwhitening[i];
}

void CYFER_DESX_Decrypt(DESX_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	int i;
	unsigned char tmp[8];

	for (i = 0; i < 8; i++) tmp[i] = input[i] ^ ctx->postwhitening[i];
	CYFER_DES_Decrypt(&(ctx->des), tmp, output);
	for (i = 0; i < 8; i++) output[i] ^= ctx->prewhitening[i];
}

