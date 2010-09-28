#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cyfer/cipher.h>

/* Iterate through stream cipher list and print supported ciphers.
 * Note that (maximum) key length is specified in bytes.
 */
static void list_sciphers(void)
{
	int i;
	CYFER_StreamCipher_t *types;

	types = CYFER_StreamCipher_Get_Supported();
	fprintf(stderr, "Supported stream ciphers:\n");
	for (i = 0; types[i].name != NULL; i++) {
		fprintf(stderr, "\t%s (%d-bit key)\n", types[i].name, types[i].keylen);
	}
}

int main(int argc, char *argv[])
{
	unsigned char plaintext[1024], ciphertext[1024];
	int type;
	unsigned char *key;
	size_t keylen, minkey, arglen;
	CYFER_STREAM_CIPHER_CTX *ctx;
	int enc = -1;

	if (argc != 3) {
		fprintf(stderr, "Usage: [enc|dec] %s <algorithm> <key>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	/* Decide whether to encrypt or decrypt data. */
	if (!strcmp(argv[1], "enc")) enc = 1;
	if (!strcmp(argv[1], "dec")) enc = 0;
	if (enc == -1) {
		fprintf(stderr, "Don't know whether to encrypt or decrypt.\n");
		exit(EXIT_FAILURE);
	}

	/* Select stream cipher to use. Also set maximum and minimum key length. For ciphers
	 * that support variable key length, the value returned is maximum key length. */
	type = CYFER_StreamCipher_Select(argv[2], &keylen, &minkey);
	if (type == CYFER_CIPHER_NONE) {
		fprintf(stderr, "Unknown algorithm: %s\n", argv[2]);
		list_sciphers();
		exit(EXIT_FAILURE);
	}

	/* Simply use user-supplied string as key, and fill unused bytes with zeroes. */
	arglen = strlen(argv[2]);
	if (arglen < keylen) keylen = (minkey > arglen) ? minkey : arglen;
	key = malloc(keylen);
	memset(key, 0, keylen);
	strncpy((char *) key, argv[2], keylen);

	/* Allocate and initialize context. Note that actual key length is supplied as
	 * 4th argument. For ciphers that don't support variable key lengths, this value
	 * is ignored. */
	ctx = CYFER_StreamCipher_Init(type, key, strlen(argv[3]));

	/* Read data (size arbitrarily limited by our buffer variables), encrypt it,
     * and output it. */
	while (1) {
		int n = fread(plaintext, 1, 1024, stdin);
		if (n < 1) break;
		if (enc)
			CYFER_StreamCipher_Encrypt(ctx, plaintext, ciphertext, n);
		else
			CYFER_StreamCipher_Decrypt(ctx, plaintext, ciphertext, n);
		fwrite(ciphertext, 1, n, stdout);
	}

	/* Finish using ciper context and delete the context. */
	CYFER_StreamCipher_Finish(ctx);

	free(key);

	return EXIT_SUCCESS;
}

