#include <stdlib.h>
#include <string.h>
#include <des.h>


/* constants and transformations */

/* Caveat: we use 64bit variables for holding blocks. Since variables
   are by definition little-endian (bits are counted from LSB) and DES
   algorithm uses big-endian notation, we must convert internally. For
   56/48/32/28-bit values, the rest (lsb part) of the variable is UNUSED!
 */
#define bit(k) (1LL << (64 - (k)))
#define rotl64(t,s) ((t << s) | (t >> (64 - s)))
#define rotl(t,s,n) ((t << s) | (t >> ((n) - s)))
#define split(val,l,r,n) { l = val & ~(bit(n) - 1); r = val << n; }
#define merge(l,r,n) ((l & ~(bit(n) - 1)) | (r >> n))

static const u8 ip[64] = {
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7
};

static const u8 ip1[64] = {
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25
};

static const u8 pc1[56] = {
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4
};

static const u8 shifts[16] = {
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

static const u8 pc2[48] = {
	14, 17, 11, 24, 1, 5,
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};

static const u8 expansion[48] = {
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1
};

static const u8 fperm[32] = {
	16, 7, 20, 21, 29, 12, 28, 17,
	1, 15, 23, 26, 5, 18, 31, 10,
	2, 8, 24, 14, 32, 27, 3, 9,
	19, 13, 30, 6, 22, 11, 4, 25
};

static const u8 sbox[8][4][16] = {
	{
		{ 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 },
		{ 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8 },
		{ 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 },
		{ 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 }
	}, {
		{ 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 },
		{ 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 },
		{ 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 },
		{ 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 }
	}, {
		{ 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 },
		{ 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 },
		{ 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 },
		{ 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 }
	}, {
		{ 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 },
		{ 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9 },
		{ 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 },
		{ 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 }
	}, {
		{ 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 },
		{ 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 },
		{ 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 },
		{ 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 }
	}, {
		{ 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 },
		{ 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 },
		{ 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 },
		{ 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 }
	}, {
		{ 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1 },
		{ 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6 },
		{ 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2 },
		{ 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 }
	}, {
		{ 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 },
		{ 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 },
		{ 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 },
		{ 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
	}
};

/* implementation */

static inline u64 permute(u64 src, const u8 *table, size_t len)
{
	u64 val = 0LL;
	unsigned int i;

	for (i = 0; i < len; i++) if (src & bit(table[i])) val |= bit(i + 1);
	return val;
}

static inline u64 des_select(u64 src)
{
	int j, m, n;
	u8 B;
	u64 val = 0LL;;

	for (j = 0; j < 8; j++) {
		B = (u8) ((src >> 58) % 64LL); src <<= 6;
		m = (B / 32) * 2 + (B & 1);
		n = (B / 2) % 16;
		val |= ((u64) sbox[j][m][n]); 
		val <<= 4;
	}
	return val << 28;
}

static void key_schedule(DES_CTX *ctx, u64 key)
{
	int i;
	u64 C, D;

	key = permute(key, pc1, 56);
	split(key, C, D, 28);

	for (i = 0; i < 16; i++) {
		C = rotl(C, shifts[i], 28);
		D = rotl(D, shifts[i], 28);
		ctx->K[i] = permute(merge(C, D, 28), pc2, 48);
	}
}

static u64 des_crypt_block(DES_CTX *ctx, u64 block, bool encipher)
{
	int i;
	u64 L, R, t, f;

	block = permute(block, ip, 64);
	split(block, L, R, 32);

	if (encipher) {
		for (i = 0; i < 16; i++) {
			f = permute(des_select(permute(R, expansion, 48) ^ ctx->K[i]), fperm, 32);
			t = R; R = L ^ f; L = t;
		}
	} else {
		for (i = 15; i >= 0; i--) {
			f = permute(des_select(permute(R, expansion, 48) ^ ctx->K[i]), fperm, 32);
			t = R; R = L ^ f; L = t;
		}
	}
	return permute(merge(R, L, 32), ip1, 64);
}

/* interface */

void CYFER_DES_Init(DES_CTX *ctx, const unsigned char *key)
{
	u64 k;
	int i;

	k = 0LL; for (i = 0; i < 8; i++) k = (k << 8) | ((u64) key[i]);
	key_schedule(ctx, k);
}

void CYFER_DES_Finish(DES_CTX *ctx)
{
	ctx = NULL; /* suppress warning */
}

void CYFER_DES_Encrypt(DES_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	u64 in, out;
	int i;

	in = 0LL;
	for (i = 0; i < 8; i++) in = (in << 8) | ((u64) input[i]);
	out = des_crypt_block(ctx, in, true);

	for (i = 0; i < 8; i++) {
		output[7 - i] = (u8) (out & 0xffll); out >>= 8;
	}
}

void CYFER_DES_Decrypt(DES_CTX *ctx, const unsigned char *input, unsigned char *output)
{
	u64 in, out;
	int i;

	in = 0LL;
	for (i = 0; i < 8; i++) in = (in << 8) | ((u64) input[i]);
	out = des_crypt_block(ctx, in, false);

	for (i = 0; i < 8; i++) {
		output[7 - i] = (u8) (out & 0xffll); out >>= 8;
	}
}

