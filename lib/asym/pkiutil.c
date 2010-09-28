#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <pkiutil.h>

#define store_big16(val, text) { (text)[0] = (u8) ((val / 256) & 255); (text)[1] = (u8) (val & 255); }
#define load_big16(text) (((u16) (text)[0]) * 256 + (u16) (text)[1])

void mpi_store(unsigned char *buf, size_t nkeys, ...)
{
	bignum_t *x;
	size_t len, tlen;
	unsigned int i;
	va_list ap;

	va_start(ap, nkeys);

	len = 0;
	for (i = 0; i < nkeys; i++) {
		x = va_arg(ap, bignum_t *);
		
		bignum_bigstore((*x), buf + 2, &tlen);
		store_big16((u16) tlen, buf);
		len += tlen; buf += 2 + tlen;
	}
	va_end(ap);
}

bool mpi_load(const unsigned char *buf, size_t len, size_t nkeys, ...)
{
	size_t i, tlen;
	va_list ap;
	bignum_t *x;

	va_start(ap, nkeys);
	for (i = 0; i < nkeys; i++) {
		x = va_arg(ap, bignum_t *);

		tlen = load_big16(buf);
		if (len < (tlen + 2)) { va_end(ap); return false; }

		buf += 2;
		bignum_bigload((*x), buf, tlen);
		buf += tlen; len -= tlen + 2;
	}
	va_end(ap);
	return true;
}

void mpi_raw_store(bignum_t x, unsigned char *buf, size_t len)
{
	size_t alen;
	unsigned char *c;

	alen = bignum_bytes_needed(x);
	c = malloc(alen);
	bignum_bigstore(x, c, &alen);

	memset(buf, 0, len);
	if (alen > len) alen = len;
	memcpy(buf + (len - alen), c, alen);

	free(c);
}

void mpi_raw_load(bignum_t x, const unsigned char *buf, size_t len)
{
	bignum_bigload(x, buf, len);
}

