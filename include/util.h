#ifndef _UTIL_H_ 
#define _UTIL_H_

#if defined(_WIN32) 

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <malloc.h>
#define inline __inline
typedef unsigned __int64 uint64_t;
typedef unsigned __int32 uint32_t;
#define CYFER_API __declspec(dllexport)

typedef unsigned int bool;
#define false 0
#define true (!false)

#else /* _WIN32 */

#define CYFER_API
#include <unistd.h>
#include <inttypes.h>
#include <config.h>
#include <stdbool.h>

#endif /* _WIN32 */

#include <stdlib.h>

typedef uint64_t u64;
typedef uint32_t u32;

typedef unsigned short u16;
typedef unsigned char u8;
typedef void *hash_context;

static inline u32 u32_load_native(const u8 *text)
{
	return *((u32 *) text);
}

static inline void u32_store_native(u32 val, u8 *text)
{
	*((u32 *) text) = val;
}

static inline u32 u32_swap(u32 val)
{
	return ((val & 0xff) << 24) | ((val & (0xff << 8)) << 8) | ((val & (0xff << 16)) >> 8) | (val >> 24);
}

#ifdef WORDS_BIGENDIAN
#define big_load32(text) u32_load_native(text)
#define big_store32(val, text) u32_store_native(val, text)
#define little_load32(text) u32_swap(u32_load_native(text))
#define little_store32(val, text) u32_store_native(u32_swap(val), text)
#else /* WORDS_BIGENDIAN */
#define little_load32(text) u32_load_native(text)
#define little_store32(val, text) u32_store_native(val, text)
#define big_load32(text) u32_swap(u32_load_native(text))
#define big_store32(val, text) u32_store_native(u32_swap(val), text)
#endif /* WORDS_BIGENDIAN */

typedef void (*cyfer_crypt_handler_t)(void *, const unsigned char *, const unsigned char *);

#define CYFER_INTERNAL

#endif /* _UTIL_H_ */

