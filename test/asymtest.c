#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <test.h>
#include <cyfer/pk.h>
#include <cyfer/keyex.h>

#define MIN_SIZE 256
#define MAX_SIZE 2048
#define KEYEX_ITER 50

static int generic_encryption(int type);
static int generic_signature(int type);
static int test(char *name, char *desc, int (*code)(int), int value);

static int keyex_test(int type);

static int keyex_test(int type)
{
	unsigned char a[MAX_SIZE], b[MAX_SIZE];
	size_t alen, blen, i;
	CYFER_KEYEX_CTX *ctx, *ctx2;

	for (i = 0; i < KEYEX_ITER; i++) {
		ctx = CYFER_KeyEx_Init(type);
		CYFER_KeyEx_Generate_Key(ctx);
		CYFER_KeyEx_KeySize(ctx, NULL, &alen);

		ctx2 = CYFER_KeyEx_Init(type);
		CYFER_KeyEx_Generate_Key(ctx2);
		CYFER_KeyEx_KeySize(ctx2, NULL, &blen);

		CYFER_KeyEx_Public_Key(ctx, a);
		CYFER_KeyEx_Public_Key(ctx2, b);

		if (!CYFER_KeyEx_Compute_Key(ctx, b, blen)) return 0;
		if (!CYFER_KeyEx_Compute_Key(ctx2, a, alen)) return 0;

		CYFER_KeyEx_Shared_Key(ctx, a, 160 / 8);
		CYFER_KeyEx_Shared_Key(ctx, b, 160 / 8);

		CYFER_KeyEx_Finish(ctx);
		CYFER_KeyEx_Finish(ctx2);

		if (memcmp(a, b, 20)) return 0;
	}

	return 1;
}

static int generic_encryption(int type)
{
	unsigned char a[MAX_SIZE], b[MAX_SIZE], c[MAX_SIZE], priv[MAX_SIZE], pub[MAX_SIZE];
	CYFER_PK_CTX *ctx;
	size_t pt_len, ct_len, privlen, publen;
	int i;

	for (i = MIN_SIZE; i <= MAX_SIZE; i += MIN_SIZE) {
		printf("%d ", i); fflush(stdout);
		ctx = CYFER_Pk_Init(type);
		CYFER_Pk_Generate_Key(ctx, i);
		CYFER_Pk_Size(ctx, &pt_len, &ct_len);
		CYFER_Pk_KeySize(ctx, &privlen, &publen);
		CYFER_Pk_Export_Key(ctx, priv, pub);
		CYFER_Pk_Finish(ctx);

		memset(a, 0, pt_len); strcpy(a, "Forty-Two");

		ctx = CYFER_Pk_Init(type);
		CYFER_Pk_Import_Key(ctx, NULL, 0, pub, publen);
		CYFER_Pk_Encrypt(ctx, a, b);
		CYFER_Pk_Finish(ctx);

		ctx = CYFER_Pk_Init(type);
		CYFER_Pk_Import_Key(ctx, priv, privlen, NULL, 0);
		CYFER_Pk_Decrypt(ctx, b, c);
		CYFER_Pk_Finish(ctx);

		if (memcmp(a, c, pt_len)) return 0;
	}

	return 1;
}

static int generic_signature(int type)
{
	unsigned char a[MAX_SIZE], b[MAX_SIZE], priv[MAX_SIZE], pub[MAX_SIZE];
	CYFER_PK_CTX *ctx;
	size_t pt_len, ct_len, privlen, publen;
	int i, retval;

	for (i = MIN_SIZE; i <= MAX_SIZE; i += MIN_SIZE) {
		printf("%d ", i); fflush(stdout);
		ctx = CYFER_Pk_Init(type);
		CYFER_Pk_Generate_Key(ctx, i);
		CYFER_Pk_Size(ctx, &pt_len, &ct_len);
		CYFER_Pk_KeySize(ctx, &privlen, &publen);
		CYFER_Pk_Export_Key(ctx, priv, pub);
		CYFER_Pk_Finish(ctx);

		memset(a, 0, pt_len); strcpy(a, "Forty-Two");

		ctx = CYFER_Pk_Init(type);
		CYFER_Pk_Import_Key(ctx, priv, privlen, NULL, 0);
		CYFER_Pk_Sign(ctx, a, b);
		CYFER_Pk_Finish(ctx);

		ctx = CYFER_Pk_Init(type);
		CYFER_Pk_Import_Key(ctx, NULL, 0, pub, publen);
		retval = CYFER_Pk_Verify(ctx, b, a);
		CYFER_Pk_Finish(ctx);

		if (!retval) return 0;
	}
	return 1;
}

static int test(char *name, char *desc, int (*code)(int), int value)
{
	printf("Testing %s %s: ", name, desc);
	fflush(stdout);
	if (code(value)) {
			printf("passed\n");
			return 1;
	}
	printf("failed\n");
	return 0;
}

void asymtest(int *nt, int *sc)
{
	int i;
	CYFER_Pk_t *pk_types;
	CYFER_KeyEx_t *keyex_types;

	pk_types = CYFER_Pk_Get_Supported();
	keyex_types = CYFER_KeyEx_Get_Supported();

	for (i = 0; keyex_types[i].type != CYFER_KEYEX_NONE; i++) {
		*nt = *nt + 1; *sc = *sc + test(keyex_types[i].name,
			"key exchange", keyex_test, keyex_types[i].type);
	}
	for (i = 0; pk_types[i].type != CYFER_PK_NONE; i++) {
		*nt = *nt + 1; *sc = *sc + test(pk_types[i].name,
				"encryption", generic_encryption, pk_types[i].type);
		*nt = *nt + 1; *sc = *sc + test(pk_types[i].name,
				"signature", generic_signature, pk_types[i].type); 
	}
}

