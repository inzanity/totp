#ifndef SHA512_H
#define SHA512_H

#include <stdlib.h>
#include <stdint.h>

#define SHA512_HASHSIZE 64
#define SHA384_HASHSIZE 48

struct sha512 {
	uint8_t buffer[128];
	uint64_t h[8];
	uint64_t len;
};

struct sha384 {
	uint8_t buffer[128];
	uint64_t h[6];
	uint64_t h6;
	uint64_t h7;
	uint64_t len;
};

void sha512_init(struct sha512 *s);
void sha512_update(struct sha512 *s, const void *data, size_t len);
void sha512_finish(struct sha512 *s);

void sha512_hmac(const void *key, size_t keylen,
		 const void *data, size_t datalen,
		 void *h);

void sha384_init(struct sha384 *s);
void sha384_update(struct sha384 *s, const void *data, size_t len);
void sha384_finish(struct sha384 *s);

void sha384_hmac(const void *key, size_t keylen,
		 const void *data, size_t datalen,
		 void *h);

#endif
