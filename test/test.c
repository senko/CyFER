#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <test.h>

int main(void)
{
	int nt, sc;

	srand((unsigned int) time(NULL));
	
	nt = 0; sc = 0;

	hashtest(&nt, &sc);
	bcipher(&nt, &sc);
	bmodes(&nt, &sc);
	scipher(&nt, &sc);
	asymtest(&nt, &sc);

	printf("Tests complete (%d success, %d failure, %d total).\n", sc, nt - sc, nt);
	if (nt == sc) return EXIT_SUCCESS;
	return EXIT_FAILURE;
}

