#ifndef SHA1_H
#define SHA1_H

#include <stdlib.h>
#include <stdint.h>

#define SHA1_HASHSIZE 20

struct sha1 {
	uint32_t buffer[16];
	uint32_t h[5];
	uint64_t len;
};

void sha1_init(struct sha1 *s);
void sha1_update(struct sha1 *s, const void *data, size_t len);
void sha1_finish(struct sha1 *s);

void sha1_hmac(const void *key, size_t keylen,
	       const void *data, size_t datalen,
	       void *h);

#endif
