#include <stdlib.h>
#include <string.h>
#include <rc2.h>


/* constants and transformations */

/* we use effective keylength of 64bits (8 bytes) */
#define T1 64
#define T8 ((T1 + 7) / 8)
#define TM (255 % (1 << (8 + T1 - 8 * T8)))

#define rotl(s,t) (((s) << (t)) | ((s) >> (16 - (t))))
#define rotr(s,t) (((s) >> (t)) | ((s) << (16 - (t))))
#define little_load16(x) (((u16) (x)[0]) + ((u16) (x)[1]) * 256)
#define little_store16(v,x) { (x)[0] = (u8) (v & 255); (x)[1] = (u8) ((v >> 8) & 255); }

#ifdef WORDS_BIGENDIAN
#define to_little(dest, src, len) swab((const void *) src, (void *) dest, len)
#else
#define to_little(dest, src, len) memmove(dest, src, len)
#endif
#define from_little to_little

static const u8 s[4] = {
	1, 2, 3, 5
};

static const u8 pitable[256] = {
	0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
	0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
	0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
	0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
	0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
	0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
	0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
	0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
	0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
	0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
	0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
	0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
	0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
	0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
	0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
	0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad
};

/* implementation */

static void key_schedule(RC2_CTX *ctx, const unsigned char *key, size_t keylen)
{
	int i;
	int T = (int) keylen;
	u8 L[128];

	for (i = 0; i < T; i++) L[i] = key[i];
	for (i = T; i < 128; i++) L[i] = pitable[(L[i - 1] + L[i - T]) % 256];
	L[128 - T8] = pitable[L[128 - T8] & TM];
	for (i = 127 - T8; i >= 0; i--) L[i] = pitable[L[i + 1] ^ L[i + T8]];
	for (i = 0; i < 64; i++) ctx->K[i] = little_load16(L + 2 * i);
}

#define mixup(i) { \
	R[i] = (R[i] + ctx->K[j] + (R[(i+3) % 4] & R[(i+2) % 4]) + ((~R[(i+3) % 4]) & R[(i+1) % 4])) & 65535U; \
	R[i] = rotl(R[i], s[i]); \
	j++; \
}
#define mixround() { mixup(0); mixup(1); mixup(2); mixup(3); }
#define mash(i) R[i] = R[i] + ctx->K[R[(i + 3) % 4] & 63]
#define mashround() { mash(0); mash(1); mash(2); mash(3); }

#define Rmixup(i) { \
	R[i] = rotr(R[i], s[i]); \
	R[i] = R[i] - ctx->K[j] - (R[(i+3) % 4] & R[(i+2) % 4]) - ((~R[(i+3) % 4]) & R[(i+1) % 4]); \
	j--; \
}

#define Rmixround() { Rmixup(3); Rmixup(2); Rmixup(1); Rmixup(0); }
#define Rmash(i) R[i] = R[i] - ctx->K[R[(i + 3) % 4] & 63]
#define Rmashround() { Rmash(3); Rmash(2); Rmash(1); Rmash(0); }

static void rc2_encrypt_block(RC2_CTX *ctx, u16 *R)
{
	u16 i, j;

	j = 0;
	for (i = 0; i < 5; i++) mixround();
	mashround();
	for (i = 0; i < 6; i++) mixround();
	mashround();
	for (i = 0; i < 5; i++) mixround();
}

static void rc2_decrypt_block(RC2_CTX *ctx, u16 *R)
{
	u16 i, j;

	j = 63;
	for (i = 0; i < 5; i++) Rmixround();
	Rmashround();
	for (i = 0; i < 6; i++) Rmixround();
	Rmashround();
	for (i = 0; i < 5; i++) Rmixround();
}

/* interface */

void CYFER_RC2_Init(RC2_CTX *ctx, const unsigned char *key, size_t keylen)
{
	key_schedule(ctx, key, keylen);
}

void CYFER_RC2_Finish(RC2_CTX *ctx)
{
	ctx = NULL; /* suppress warning */
}

void CYFER_RC2_Encrypt(RC2_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	u16 *buf = (u16 *) output;

	to_little(output, input, 8);
	rc2_encrypt_block(ctx, buf);
	from_little(output, output, 8);
}

void CYFER_RC2_Decrypt(RC2_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	u16 *buf = (u16 *) output;

	to_little(output, input, 8);
	rc2_decrypt_block(ctx, buf);
	from_little(output, output, 8);
}

