#ifndef _PKIUTIL_H_
#define _PKIUTIL_H_

#include <bignum.h>

#ifdef __cplusplus
extern "C" {
#endif
	
void mpi_store(unsigned char *buf, size_t nkeys, ...);
bool mpi_load(const unsigned char *buf, size_t len, size_t nkeys, ...);

void mpi_raw_store(bignum_t x, unsigned char *buf, size_t len);
void mpi_raw_load(bignum_t x, const unsigned char *buf, size_t len);

#ifdef __cplusplus
};
#endif

#endif /* _PKIUTIL_H_ */

