/** \mainpage Cyfer cryptographic library
  *
  * \section intro Introduction
  *
  * Cyfer is a portable cryptographic library providing several implementations
  * of message digest, block and stream cipher and public-key algorithms.
  * The library is extremely modular, providing easy way to add or modify
  * algorithm implementations, or even separating the particular algorithm
  * from the library physically (suitable for embedded environments).
  *
  * The library design concept emphasises on simplicity and elegance (of both
  * the algorithm implementations (where possible) and the support library
  * code), not maximizing performance or minimizing memory footprint. The
  * algorithm implementations are straightforward, so they can be used for
  * educational purposes.
  *
  * Cyfer is portable to any platform with sane C development environment, the
  * only requirement being the availability of the GNU MP (Multiple Precision
  * arithmetic) library. As the GMP is used only for public-key cryptography,
  * hash or symmetric cipher components should work everywhere.
  *
  * The library is known to compile and run in Linux, FreeBSD, Solaris and
  * Windows operating systems, on x86 (32-bit, little-endian) and sparc9
  * (64-bit, big-endian) architectures.
  *
  * \section feat Features
  *
  * Hash algorithms: Adler-32, CRC-32, MD2, MD4, MD5, RIPEMD-160, SHA-1, SHA-256, Snefru \n
  * Block ciphers: AES, Blowfish, DEAL, DES, DESX, TripleDES, IDEA, RC2, RC5, RC6, ThreeWay \n
  * Block cipher modes of operation: ECB, CBC, CFB, OFB \n
  * Stream ciphers: RC4 (ArcFour) \n
  * Public-key cryptography: ElGamal, LUC, RSA \n
  * Key-exchange algorithms: Diffie-Hellman \n
  *
  * \section ref Library reference
  *
  * \link hash.h Hash (message digest) algorithm support \endlink \n
  * \link cipher.h Block and stream (symmetric) cipher support \endlink \n
  * \link pk.h Public-key (asymmetric) cryptography support \endlink \n
  * \link keyex.h Key-exchange algorithm support \endlink \n
  *
  *
  * \section copy Author and copyright
  *
  * \author Senko Rasic <senko@senko.net>
  *
  * Cyfer is free software. You may use and/or distribute it under the terms of
  * the BSD software license, see the file LICENSE for details.
  *
  * \warning Cyfer is provided with best intent to be useful and secure, but
  * with no warranty; it is not heavily tested and may contain numerous severe
  * bugs, flaws and holes - if security is your #1 goal, the wisest choice is
  * to use tested, proven and certified cryptography implementation.
  */

#ifndef _CYFER_H_
#define _CYFER_H_

#include <stdlib.h>

#if defined(_WIN32)
#define CYFER_API __declspec(dllimport)
typedef unsigned int bool;
#define false 0
#define true (!0)
#else
#define CYFER_API
#include <stdbool.h>
#endif

#endif /* _CYFER_H_ */

