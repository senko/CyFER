#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cyfer/pk.h>

/* Iterate through public-key algorithm list and print it. */
static void list_pks(void)
{
	int i;
	CYFER_Pk_t *types;
	
	types = CYFER_Pk_Get_Supported();
	fprintf(stderr, "Supported public-key algorithms:\n");
	for (i = 0; types[i].name != NULL; i++) {
		fprintf(stderr, "\t%s (encryption: %s, signature: %s)\n", types[i].name,
				types[i].encryption ? "yes" : "no",
				types[i].signature ? "yes" : "no");
	}
}

/* Helper function for creating public-key context. */
static CYFER_PK_CTX *init_ctx(char *pk)
{
	int type;
	bool enc, sig;
	CYFER_PK_CTX *ctx;

	/* Select and initialize the desired algorithm or fail miserably */
	type = CYFER_Pk_Select(pk, &enc, &sig);
	if (type == CYFER_PK_NONE) {
		fprintf(stderr, "Error while generating keys: No such algorithm: %s\n", pk);
		list_pks();
		exit(EXIT_FAILURE);
	}
	ctx = CYFER_Pk_Init(type);
	if (!ctx) {
		perror("Error while generating keys");
		exit(EXIT_FAILURE);
	}
	return ctx;
}

/* Generate new public/private key pair of selected size (in bits) for selected
   algorithm, and save them in separate files. */
static int generate_keys(char *pk, int size, char *pubfile, char *privfile)
{
	CYFER_PK_CTX *ctx;
	FILE *fp;
	int privlen, publen;
	char *priv, *pub;

	/* Create context */
	ctx = init_ctx(pk);

	/* Generate and export keys into temporary buffers */
	printf("Generating keys, please wait ...\n");
	CYFER_Pk_Generate_Key(ctx, size);
	CYFER_Pk_KeySize(ctx, &privlen, &publen);

	priv = malloc(privlen);
	pub = malloc(publen);

	CYFER_Pk_Export_Key(ctx, priv, pub);
	CYFER_Pk_Finish(ctx);

	/* Save the buffers */
	fp = fopen(pubfile, "wb");
	if (!fp) {
		perror("Error while generating keys: Can't open public key file");
		free(priv); free(pub);
		exit(EXIT_FAILURE);
	}

	fwrite(pub, publen, 1, fp);
	fclose(fp);

	fp = fopen(privfile, "wb");
	if (!fp) {
		perror("Error while generating keys: Can't open private key file");
		free(priv); free(pub);
		exit(EXIT_FAILURE);
	}

	fwrite(priv, privlen, 1, fp);
	fclose(fp);

	printf("New %s %d-bit key pair successfully generated\n", pk, size);
	free(priv); free(pub);
	exit(EXIT_SUCCESS);
}

/* Perform encryption or decryption. */
static void encdec(char *pk, char *keyfile, char *infile, char *outfile, bool encrypt)
{
	FILE *fp, *in, *out;
	char *key;
	int klen;
	size_t in_len, out_len;
	char *inbuf, *outbuf;
	bool import;
	int n;
	CYFER_PK_CTX *ctx;

	/* Create context */
	ctx = init_ctx(pk);

	/* Import the key. */
	fp = fopen(keyfile, "rb");
	if (!fp) {
		perror("Can't open key file");
		exit(EXIT_FAILURE);
	}
	fseek(fp, 0, SEEK_END);
	klen = ftell(fp);
	rewind(fp);

	key = malloc(klen);
	fread(key, klen, 1, fp);
	fclose(fp);

	if (encrypt) {
		import = CYFER_Pk_Import_Key(ctx, NULL, 0, key, klen);
		CYFER_Pk_Size(ctx, &in_len, &out_len);
	} else {
		import = CYFER_Pk_Import_Key(ctx, key, klen, NULL, 0);
		CYFER_Pk_Size(ctx, &out_len, &in_len);
	}

	if (!import) {
		fprintf(stderr, "Failed to import the key\n");
		free(key);
		exit(EXIT_FAILURE);
	}

	/* Create data buffers */

	inbuf = malloc(in_len);
	outbuf = malloc(out_len);

	in = fopen(infile, "rb");
	if (!in) {
		perror("Can't open input file");
		free(key); free(inbuf); free(outbuf);
		exit(EXIT_FAILURE);
	}

	out = fopen(outfile, "wb");
	if (!out) {
		perror("Can't write to output file");
		free(key); free(inbuf); free(outbuf);
		exit(EXIT_FAILURE);
	}
	
	/* Encrypt or decrypt. For incomplete block, this assumes the remainder
	 * is filled with zeroes.  */
	while (1) {
		memset(inbuf, 0, in_len);
		n = fread(inbuf, 1, in_len, in);
		if (n <= 0) break;
		if (encrypt)
			CYFER_Pk_Encrypt(ctx, inbuf, outbuf);
		else
			CYFER_Pk_Decrypt(ctx, inbuf, outbuf);
		fwrite(outbuf, 1, out_len, out);
	}

	CYFER_Pk_Finish(ctx);
	free(key); free(inbuf); free(outbuf);
}

int main(int argc, char *argv[])
{
	bool enc;

	if (argc != 6) {
		fprintf(stderr, "Usage: %s gen <algorithm> <keysize> <privfile> <pubfile>\n", argv[0]);
		fprintf(stderr, "          enc <algorithm> <pubfile> <infile> <outfile>\n");
		fprintf(stderr, "          dec <algorithm> <privfile> <infile> <outfile>\n");
		return EXIT_FAILURE;
	}

	if (!strcmp(argv[1], "gen"))
		generate_keys(argv[2], atoi(argv[3]), argv[4], argv[5]);

	if (!strcmp(argv[1], "enc")) {
		enc = true;
	} else if (!strcmp(argv[1], "dec")) {
		enc = false;
	} else {
		fprintf(stderr, "%s: unrecognized command\n", argv[0]);
		return EXIT_FAILURE;
	}

	encdec(argv[2], argv[3], argv[4], argv[5], enc);

	return EXIT_SUCCESS;
}

