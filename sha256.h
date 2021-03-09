#ifndef SHA256_H
#define SHA256_H

#include <stdlib.h>
#include <stdint.h>

#define SHA256_HASHSIZE 32
#define SHA224_HASHSIZE 28

struct sha256 {
	uint8_t buffer[64];
	uint32_t h[8];
	uint64_t len;
};

struct sha224 {
	uint8_t buffer[64];
	uint32_t h[7];
	uint32_t h7;
	uint64_t len;
};

void sha256_init(struct sha256 *s);
void sha256_update(struct sha256 *s, const void *data, size_t len);
void sha256_finish(struct sha256 *s);

void sha256_hmac(const void *key, size_t keylen,
		 const void *data, size_t datalen,
		 void *h);

void sha224_init(struct sha224 *s);
void sha224_update(struct sha224 *s, const void *data, size_t len);
void sha224_finish(struct sha224 *s);

void sha224_hmac(const void *key, size_t keylen,
		 const void *data, size_t datalen,
		 void *h);

#endif
