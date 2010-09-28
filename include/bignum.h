#ifndef _BIGNUM_H_
#define _BIGNUM_H_

#include <gmp.h>
#include <util.h>

typedef mpz_t bignum_t;
typedef gmp_randstate_t randstate_t;

static inline void bignum_random_init(randstate_t state, u32 seed)
{
	gmp_randinit_default(state);
	gmp_randseed_ui(state, seed);
}

static inline void bignum_bigload(bignum_t val, const unsigned char *buf, size_t len)
{
	mpz_import(val, len, 1, 1, 1, 0, buf);
}

static inline void bignum_littleload(bignum_t val, const unsigned char *buf, size_t len)
{
	mpz_import(val, len, -1, 1, -1, 0, buf);
}

static inline void bignum_bigstore(bignum_t val, unsigned char *buf, size_t *len)
{
	mpz_export(buf, len, 1, 1, 1, 0, val);
}

static inline void bignum_littlestore(bignum_t val, unsigned char *buf, size_t *len)
{
	mpz_export(buf, len, -1, 1, -1, 0, val);
}

#define bignum_random_free gmp_randclear
#define bignum_init mpz_init
#define bignum_init_set mpz_init_set
#define bignum_init_set_u32 mpz_init_set_ui
#define bignum_free mpz_clear
#define bignum_set_str mpz_set_str
#define bignum_set mpz_set
#define bignum_random_bits(rop, state, keylen) mpz_urandomb(rop, state, (unsigned long) keylen)
#define bignum_random_max mpz_urandomm

#define bignum_add mpz_add
#define bignum_add_u32 mpz_add_ui
#define bignum_sub mpz_sub
#define bignum_sub_u32 mpz_sub_ui
#define bignum_mul mpz_mul
#define bignum_mul_u32 mpz_mul_ui
#define bignum_div mpz_div
#define bignum_div_u32 mpz_div_ui
#define bignum_mod mpz_mod
#define bignum_mod_u32 mpz_mod_ui
#define bignum_cmp mpz_cmp
#define bignum_cmp_u32 mpz_cmp_ui
#define bignum_sgn mpz_sgn

#define bignum_nextprime mpz_nextprime
#define bignum_lcm mpz_lcm
#define bignum_gcd mpz_gcd
#define bignum_invert mpz_invert
#define bignum_pow mpz_pow
#define bignum_powm mpz_powm

#define bignum_bits_needed(x) mpz_sizeinbase(x, 2)
#define bignum_bytes_needed(x) ((bignum_bits_needed(x) + 7) / 8)

static inline void bignum_relprime(bignum_t rop, bignum_t op, bignum_t max, randstate_t state)
{
	bignum_t t;

	bignum_init(t);

	bignum_random_max(rop, state, max);

	while (1) {
		if (bignum_cmp(rop, max) >= 0) bignum_random_max(rop, state, max);
		bignum_gcd(t, rop, op);
		if (!bignum_cmp_u32(t, 1)) break;
		bignum_add_u32(rop, rop, 1);
	}

	bignum_free(t);
}

#endif /* _BIGNUM_H_ */

