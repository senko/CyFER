#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <test.h>
#include <cyfer/hash.h>

struct slave {
	char *text;
	char *digest;
};

struct test {
	char *name;
	struct slave *tests;
};


static struct slave crc32_data[] = {
	{ "", "\x00\x00\x00\x00" },
	{ "a", "\x43\xbe\xb7\xe8" },
	{ "abc", "\xc2\x41\x24\x35" },
	{ "message digest", "\x7f\x9d\x15\x20" },
	{ "abcdefghijklmnopqrstuvwxyz", "\xbd\x50\x27\x4c" },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "\x5f\x3f\x1a\x17" },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "\xd2\xe6\xc2\x1f" },
	{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "\x72\x4a\xa9\x7c" },
	{ "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "\x49\x33\x1f\x19" },
	{ NULL, NULL }
};

static struct slave adler32_data[] = {
	{ "", "\x00\x00\x00\x01" },
	{ "a", "\x00\x62\x00\x62" },
	{ "abc", "\x02\x4d\x01\x27" },
	{ "message digest", "\x29\x75\x05\x86" },
	{ "abcdefghijklmnopqrstuvwxyz", "\x90\x86\x0b\x20" },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "\x80\x74\x16\xf9" },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "\x8a\xdb\x15\x0c" },
	{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "\x97\xb6\x10\x69" },
	{ "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "\x1a\xc2\x2e\xd1" },
	{ NULL, NULL }
};

static struct slave md2_data[] = {
	{ "", "\x83\x50\xe5\xa3\xe2\x4c\x15\x3d\xf2\x27\x5c\x9f\x80\x69\x27\x73" },
	{ "a", "\x32\xec\x01\xec\x4a\x6d\xac\x72\xc0\xab\x96\xfb\x34\xc0\xb5\xd1" },
	{ "abc", "\xda\x85\x3b\x0d\x3f\x88\xd9\x9b\x30\x28\x3a\x69\xe6\xde\xd6\xbb" },
	{ "message digest", "\xab\x4f\x49\x6b\xfb\x2a\x53\x0b\x21\x9f\xf3\x30\x31\xfe\x06\xb0" },
	{ "abcdefghijklmnopqrstuvwxyz", "\x4e\x8d\xdf\xf3\x65\x02\x92\xab\x5a\x41\x08\xc3\xaa\x47\x94\x0b" },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "\x0d\xff\x6b\x39\x8a\xd5\xa6\x2a\xc8\xd9\x75\x66\xb8\x0c\x3a\x7f" },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "\xda\x33\xde\xf2\xa4\x2d\xf1\x39\x75\x35\x28\x46\xc3\x03\x38\xcd" },
	{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "\xd5\x97\x6f\x79\xd8\x3d\x3a\x0d\xc9\x80\x6c\x3c\x66\xf3\xef\xd8" },
	{ "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "\x2c\x19\x4d\x03\x76\x41\x1d\xc0\xb8\x48\x5d\x3a\xbe\x2a\x4b\x6b" },
	{ NULL, NULL }
};

static struct slave md4_data[] = {
	{ "", "\x31\xd6\xcf\xe0\xd1\x6a\xe9\x31\xb7\x3c\x59\xd7\xe0\xc0\x89\xc0" },
	{ "a", "\xbd\xe5\x2c\xb3\x1d\xe3\x3e\x46\x24\x5e\x05\xfb\xdb\xd6\xfb\x24" },
	{ "abc", "\xa4\x48\x01\x7a\xaf\x21\xd8\x52\x5f\xc1\x0a\xe8\x7a\xa6\x72\x9d" },
	{ "message digest", "\xd9\x13\x0a\x81\x64\x54\x9f\xe8\x18\x87\x48\x06\xe1\xc7\x01\x4b" },
	{ "abcdefghijklmnopqrstuvwxyz", "\xd7\x9e\x1c\x30\x8a\xa5\xbb\xcd\xee\xa8\xed\x63\xdf\x41\x2d\xa9" },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "\x46\x91\xa9\xec\x81\xb1\xa6\xbd\x1a\xb8\x55\x72\x40\xb2\x45\xc5" },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "\x04\x3f\x85\x82\xf2\x41\xdb\x35\x1c\xe6\x27\xe1\x53\xe7\xf0\xe4" },
	{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "\xe3\x3b\x4d\xdc\x9c\x38\xf2\x19\x9c\x3e\x7b\x16\x4f\xcc\x05\x36" },
	{ "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "\x21\x02\xd1\xd9\x4b\xd5\x8e\xbf\x5a\xa2\x5c\x30\x5b\xb7\x83\xad" },
	{ NULL, NULL }
};

static struct slave md5_data[] = {
	{ "", "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e" },
	{ "a", "\x0c\xc1\x75\xb9\xc0\xf1\xb6\xa8\x31\xc3\x99\xe2\x69\x77\x26\x61" },
	{ "abc", "\x90\x01\x50\x98\x3c\xd2\x4f\xb0\xd6\x96\x3f\x7d\x28\xe1\x7f\x72" },
	{ "message digest", "\xf9\x6b\x69\x7d\x7c\xb7\x93\x8d\x52\x5a\x2f\x31\xaa\xf1\x61\xd0" },
	{ "abcdefghijklmnopqrstuvwxyz", "\xc3\xfc\xd3\xd7\x61\x92\xe4\x00\x7d\xfb\x49\x6c\xca\x67\xe1\x3b" },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "\x82\x15\xef\x07\x96\xa2\x0b\xca\xaa\xe1\x16\xd3\x87\x6c\x66\x4a" },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "\xd1\x74\xab\x98\xd2\x77\xd9\xf5\xa5\x61\x1c\x2c\x9f\x41\x9d\x9f" },
	{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "\x57\xed\xf4\xa2\x2b\xe3\xc9\x55\xac\x49\xda\x2e\x21\x07\xb6\x7a" },
	{ "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "\x03\xdd\x88\x07\xa9\x31\x75\xfb\x06\x2d\xfb\x55\xdc\x7d\x35\x9c" },
	{ NULL, NULL }
};

static struct slave sha1_data[] = {
	{ "", "\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90\xaf\xd8\x07\x09" },
	{ "a", "\x86\xf7\xe4\x37\xfa\xa5\xa7\xfc\xe1\x5d\x1d\xdc\xb9\xea\xea\xea\x37\x76\x67\xb8" },
	{ "abc", "\xa9\x99\x3e\x36\x47\x06\x81\x6a\xba\x3e\x25\x71\x78\x50\xc2\x6c\x9c\xd0\xd8\x9d" },
	{ "message digest", "\xc1\x22\x52\xce\xda\x8b\xe8\x99\x4d\x5f\xa0\x29\x0a\x47\x23\x1c\x1d\x16\xaa\xe3" },
	{ "abcdefghijklmnopqrstuvwxyz", "\x32\xd1\x0c\x7b\x8c\xf9\x65\x70\xca\x04\xce\x37\xf2\xa1\x9d\x84\x24\x0d\x3a\x89" },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "\x84\x98\x3e\x44\x1c\x3b\xd2\x6e\xba\xae\x4a\xa1\xf9\x51\x29\xe5\xe5\x46\x70\xf1" },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "\x76\x1c\x45\x7b\xf7\x3b\x14\xd2\x7e\x9e\x92\x65\xc4\x6f\x4b\x4d\xda\x11\xf9\x40" },
	{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "\x50\xab\xf5\x70\x6a\x15\x09\x90\xa0\x8b\x2c\x5e\xa4\x0f\xa0\xe5\x85\x55\x47\x32" },
	{ "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "\xa4\x9b\x24\x46\xa0\x2c\x64\x5b\xf4\x19\xf9\x95\xb6\x70\x91\x25\x3a\x04\xa2\x59" },
	{ NULL, NULL }
};


static struct slave sha256_data[] = {
	{ "", "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55" },
	{ "a", "\xca\x97\x81\x12\xca\x1b\xbd\xca\xfa\xc2\x31\xb3\x9a\x23\xdc\x4d\xa7\x86\xef\xf8\x14\x7c\x4e\x72\xb9\x80\x77\x85\xaf\xee\x48\xbb" },
	{ "abc", "\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad" },
	{ "message digest", "\xf7\x84\x6f\x55\xcf\x23\xe1\x4e\xeb\xea\xb5\xb4\xe1\x55\x0c\xad\x5b\x50\x9e\x33\x48\xfb\xc4\xef\xa3\xa1\x41\x3d\x39\x3c\xb6\x50" },
	{ "abcdefghijklmnopqrstuvwxyz", "\x71\xc4\x80\xdf\x93\xd6\xae\x2f\x1e\xfa\xd1\x44\x7c\x66\xc9\x52\x5e\x31\x62\x18\xcf\x51\xfc\x8d\x9e\xd8\x32\xf2\xda\xf1\x8b\x73" },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1" },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "\xdb\x4b\xfc\xbd\x4d\xa0\xcd\x85\xa6\x0c\x3c\x37\xd3\xfb\xd8\x80\x5c\x77\xf1\x5f\xc6\xb1\xfd\xfe\x61\x4e\xe0\xa7\xc8\xfd\xb4\xc0" },
	{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "\xf3\x71\xbc\x4a\x31\x1f\x2b\x00\x9e\xef\x95\x2d\xd8\x3c\xa8\x0e\x2b\x60\x02\x6c\x8e\x93\x55\x92\xd0\xf9\xc3\x08\x45\x3c\x81\x3e" },
	{ "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "\xcf\x5b\x16\xa7\x78\xaf\x83\x80\x03\x6c\xe5\x9e\x7b\x04\x92\x37\x0b\x24\x9b\x11\xe8\xf0\x7a\x51\xaf\xac\x45\x03\x7a\xfe\xe9\xd1" },
	{ NULL, NULL }
};

static struct slave rmd160_data[] = {
	{ "", "\x9c\x11\x85\xa5\xc5\xe9\xfc\x54\x61\x28\x08\x97\x7e\xe8\xf5\x48\xb2\x25\x8d\x31" },
	{ "a", "\x0b\xdc\x9d\x2d\x25\x6b\x3e\xe9\xda\xae\x34\x7b\xe6\xf4\xdc\x83\x5a\x46\x7f\xfe" },
	{ "abc", "\x8e\xb2\x08\xf7\xe0\x5d\x98\x7a\x9b\x04\x4a\x8e\x98\xc6\xb0\x87\xf1\x5a\x0b\xfc" },
	{ "message digest", "\x5d\x06\x89\xef\x49\xd2\xfa\xe5\x72\xb8\x81\xb1\x23\xa8\x5f\xfa\x21\x59\x5f\x36" },
	{ "abcdefghijklmnopqrstuvwxyz", "\xf7\x1c\x27\x10\x9c\x69\x2c\x1b\x56\xbb\xdc\xeb\x5b\x9d\x28\x65\xb3\x70\x8d\xbc" },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "\x12\xa0\x53\x38\x4a\x9c\x0c\x88\xe4\x05\xa0\x6c\x27\xdc\xf4\x9a\xda\x62\xeb\x2b" },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "\xb0\xe2\x0b\x6e\x31\x16\x64\x02\x86\xed\x3a\x87\xa5\x71\x30\x79\xb2\x1f\x51\x89" },
	{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "\x9b\x75\x2e\x45\x57\x3d\x4b\x39\xf4\xdb\xd3\x32\x3c\xab\x82\xbf\x63\x32\x6b\xfb" },
	{ "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "\x6f\x3f\xa3\x9b\x6b\x50\x3c\x38\x4f\x91\x9a\x49\xa7\xaa\x5c\x2c\x08\xbd\xfb\x45" },
	{ NULL, NULL }
};


static struct slave snefru_data[] = {
	{ "", "\x86\x17\xf3\x66\x56\x6a\x01\x18\x37\xf4\xfb\x4b\xa5\xbe\xde\xa2" },
	{ "abc", "\x55\x3d\x06\x48\x92\x82\x99\xa0\xf2\x2a\x27\x5a\x02\xc8\x3b\x10" },
	{ "abcdefghijklmnopqrstuvwxyz", "\x78\x40\x14\x8a\x66\xb9\x1c\x21\x9c\x36\xf1\x27\xa0\x92\x96\x06" },
	{ "The quick brown fox jumps over the lazy dog.", "\x06\xcc\x3a\x5d\xee\xea\x8f\x40\x7d\xcd\x30\x9f\x28\x33\x7f\xc2" },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "\x0e\xfd\x7f\x93\xa5\x49\xf0\x23\xb7\x97\x81\x09\x04\x58\x92\x3e" },
	{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "\xd9\x20\x4e\xd8\x0b\xb8\x43\x0c\x0b\x9c\x24\x4f\xe4\x85\x81\x4a" },
	{ NULL, NULL }
};


static struct test test_data[] = {
	{ "CRC-32", crc32_data },
	{ "Adler-32", adler32_data },
	{ "MD2", md2_data },
	{ "MD4", md4_data },
	{ "MD5", md5_data },
	{ "SHA-1", sha1_data },
	{ "SHA-256", sha256_data },
	{ "RIPEMD-160", rmd160_data },
	{ "Snefru", snefru_data },
	{ NULL, NULL }
};

void hashtest(int *nt, int *sc)
{
	unsigned char *data;
	unsigned char tmp[1024];
	int i, j, type, ok;
	size_t mdlen;

	for (i = 0; test_data[i].name; i++) {
		type = CYFER_Hash_Select(test_data[i].name, &mdlen);
		if (type == CYFER_HASH_NONE) {
			fprintf(stderr, "Unknown algorithm `%s'\n", test_data[i].name);
			continue;
		}
		*nt = *nt + 1;
		printf("Testing %s hash ... ", test_data[i].name);

		ok = 1;
		for (j = 0; test_data[i].tests[j].text; j++) {
			data = (unsigned char *) test_data[i].tests[j].text;
			CYFER_Hash(type, data, strlen((char *) data), tmp);

			if (memcmp(test_data[i].tests[j].digest, tmp, mdlen)) {
				ok = 0;
				break;
			}
		}

		if (ok) {
			*sc = *sc + 1;
			printf("passed\n");
		} else {
			printf("failed\n");
		}
	}
}

