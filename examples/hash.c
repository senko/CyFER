#include <stdio.h>
#include <stdlib.h>
#include <cyfer/hash.h>


/* Iterate through supported hash types array and display supported
 * hash algorithms and their bitlengths. The length field of the hash type
 * structure contains the length of output sum in BYTES, so we must multiply
 * the value by 8.
 */
static void list_hash_algorithms(void)
{
	int i;
	CYFER_Hash_t *types;

	types = CYFER_Hash_Get_Supported();
	fprintf(stderr, "Supported algorithms:\n");
	for (i = 0; types[i].name != NULL; i++) {
		fprintf(stderr, "\t%s (%d-bit)\n", types[i].name, types[i].length * 8);
	}
}

/* Print the resulting 8*len -bit value in human-readable form, as a sequence
 * of len hexadecimal numbers, each representing one byte.
 */
static void print_result(char *type, unsigned char *result, size_t len)
{
	int i;
	printf("%s hash: ", type);
	for (i = 0; i < len; i++) printf("%02x", result[i]);
	printf("\n");
}

/* Use first (and only) program argument to select hash type. Read data from
 * standard input, upon EOF output resulting hash value to standard output.
 */
int main(int argc, char *argv[])
{
	unsigned char tmp[1024];
	int type;
	size_t len;
	unsigned char *result;
	CYFER_HASH_CTX *ctx;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <algorithm>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	/* Convert algorithm name to integer representing its type. We can do this
	 * manually, like in list_hash_algoritms(), but this operation is frequent
	 * so there's an utility function which does this for us. */
	type = CYFER_Hash_Select(argv[1], &len);
	if (type == CYFER_HASH_NONE) {
		fprintf(stderr, "Unknown algorithm: %s\n", argv[1]);
		list_hash_algorithms();
		exit(EXIT_FAILURE);
	}
	/* Create and initialize hash context. */
	ctx = CYFER_Hash_Init(type);

	/* Process each chunk of data. */
	while (1) {
		int n = fread(tmp, 1, 1024, stdin);
		if (n < 1) break;
		CYFER_Hash_Update(ctx, tmp, n);
	}

	/* Finalize hashing process and get resulting data of length 'len'. */
	result = malloc(len);
	CYFER_Hash_Finish(ctx, result);

	print_result(argv[1], result, len);

	free(result);

	return EXIT_SUCCESS;
}

