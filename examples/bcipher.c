#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cyfer/cipher.h>

/* Iterate through block cipher list and print supported ciphers.
 * Note that (maximum) key length and block length values are specified
 * in bytes.
 */
static void list_bciphers(void)
{
	int i;
	CYFER_BlockCipher_t *types;

	types = CYFER_BlockCipher_Get_Supported();
	fprintf(stderr, "Supported block ciphers:\n");
	for (i = 0; types[i].name != NULL; i++) {
		fprintf(stderr, "\t%s (%d-bit key, %d-bit block)\n",
				types[i].name, types[i].keylen * 8, types[i].length * 8);
	}
}

/* Iterate through block mode list and print supported modes. */
static void list_bmodes(void)
{
	int i;
	CYFER_BlockMode_t *modes;

	modes = CYFER_BlockCipher_Get_SupportedModes();
	fprintf(stderr, "Supported block modes:");
	for (i = 0; modes[i].name != NULL; i++) {
		fprintf(stderr, " %s", modes[i].name);
		if (modes[i].length) fprintf(stderr, " (%d-bit block)", modes[i].length);
	}
}

int main(int argc, char *argv[])
{
	int type, mode, n;
	size_t keylen, mklen, arglen, mlen, len;
	char *key, *plaintext, *ciphertext;
	CYFER_BLOCK_CIPHER_CTX *ctx;
	int enc = -1;

	if (argc != 5) {
		fprintf(stderr, "Usage: %s [enc|dec] <algorithm> <mode> <key>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	/* Decide whether to encrypt or decrypt data. */
	if (!strcmp(argv[1], "enc")) enc = 1;
	if (!strcmp(argv[1], "dec")) enc = 0;
	if (enc == -1) {
		fprintf(stderr, "Don't know whether to encrypt or decrypt.\n");
		exit(EXIT_FAILURE);
	}

	/* Select block cipher to use. Also set algorithm data block length, and key
	 * length. For ciphers that support variable key length, the value returned
	 * is maximum key length. Those ciphers can be identifyed by inspecting the
	 * minimum key length value; if mklen != keylen, variable keys are supported */
	type = CYFER_BlockCipher_Select(argv[2], &keylen, &mklen, &len);
	if (type == CYFER_CIPHER_NONE) {
		fprintf(stderr, "Unknown algorithm: %s\n", argv[2]);
		list_bciphers();
		exit(EXIT_FAILURE);
	}

	/* Select block mode to use. */
	mode = CYFER_BlockCipher_SelectMode(argv[3], &mlen);
	if (mode == CYFER_MODE_NONE) {
		fprintf(stderr, "Unknown block cipher mode: %s\n", argv[3]);
		list_bmodes();
		exit(EXIT_FAILURE);
	}
	/* Some modes (CFB, OFB) override cipher's block size (e.g. to 1 byte "blocks").
	 * This is useful when each byte must be processed immediately (e.g. for interactive
	 * sessions. Note that the entire computation is performed for each byte, so these
	 * modes have much worse performanse than ECB or CBC. */
	if (mlen) len = mlen;

	/* Simply use user-supplied string as key, and fill unused bytes with zeroes.
	 * If variable-length key is supported, minimum key length is 'mklen'. */
	arglen = strlen(argv[2]);
	if (arglen < keylen) {
		keylen = (mklen > arglen) ? mklen : arglen;
	}
	key = malloc(keylen);
	memset(key, 0, keylen);
	strncpy(key, argv[2], keylen);

	/* Allocate and initialize context. Note that actual key length is supplied as
	 * 3rd argument. For ciphers that don't support variable key lengths, this value
	 * is ignored. The 4th argument selects desired block cipher mode of operation,
     * and 5th sets the initialization vector. If NULL is supplied, initialization
	 * vector is zero. */
	ctx = CYFER_BlockCipher_Init(type, key, strlen(argv[2]), mode, NULL);

	plaintext = malloc(len);
	ciphertext = malloc(len);

	/* Read block of data, encrypt it, output it. For incomplete block, this
	 * assumes the remainder is filled with zeroes. */  
	while (1) {
		memset(plaintext, 0, len);
		n = fread(plaintext, 1, len, stdin);
		if (n < 1) break;
		if (enc)
				CYFER_BlockCipher_Encrypt(ctx, plaintext, ciphertext);
		else
				CYFER_BlockCipher_Decrypt(ctx, plaintext, ciphertext);
		fwrite(ciphertext, 1, len, stdout);
	}

	/* Finish using ciper context and delete the context. */
	CYFER_BlockCipher_Finish(ctx);

	free(key);
	free(plaintext);
	free(ciphertext);

	return EXIT_SUCCESS;
}

