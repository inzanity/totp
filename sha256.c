#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <arpa/inet.h>

#include "sha256.h"
#include "util.h"

static inline uint32_t rotr32(uint32_t x, uint8_t n)
{
	return x >> n | x << (32 - n);
}

static inline void add8(uint32_t *dest, const uint32_t *src)
{
	size_t i;

	for (i = 0; i < 8; i++)
		dest[i] += src[i];
}

static inline void rotmod8(uint32_t *a, uint32_t k, uint32_t w)
{
	uint32_t t1 = a[7] + (rotr32(a[4], 6) ^ rotr32(a[4], 11) ^ rotr32(a[4], 25)) + ((a[4] & a[5]) ^ (~a[4] & a[6])) + k + w;
	uint32_t t2 = (rotr32(a[0], 2) ^ rotr32(a[0], 13) ^ rotr32(a[0], 22)) + ((a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]));

	memmove(a + 1, a, 7 * sizeof(*a));

	a[4] += t1;
	a[0] = t1 + t2;
}

static inline uint32_t getnw(uint32_t *w, size_t i)
{
	return w[i & 15] +=
		(rotr32(w[(i + 1) & 15], 7) ^ rotr32(w[(i + 1) & 15], 18) ^ (w[(i + 1) & 15] >> 3)) +
		w[(i + 9) & 15] +
		(rotr32(w[(i + 14) & 15], 17) ^ rotr32(w[(i + 14) & 15], 19) ^ (w[(i + 14) & 15] >> 10));
}

void sha256_init(struct sha256 *s)
{
	memcpy(s->h, (uint32_t[]){ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }, sizeof(s->h));
	s->len = 0;
}

static inline void _sha256_update(uint32_t *h, const void *data)
{
	const uint32_t k[] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	}; 
	const uint32_t *d = data;

	uint32_t w[16];
	size_t i;

	uint32_t wr[8];
	memcpy(wr, h, sizeof(wr));

	for (i = 0; i < 16; i++)
		rotmod8(wr, k[i], w[i] = ntohl(d[i]));

	for (; i < 64; i++)
		rotmod8(wr, k[i], getnw(w, i));

	add8(h, wr);
}

void sha256_update(struct sha256 *s, const void *data, size_t len)
{
	if ((s->len & 63) + len >= 64) {
		const char *d = data;
		if (s->len & 63) {
			memcpy(s->buffer + (s->len & 63), d, 64 - (s->len & 63));
			_sha256_update(s->h, s->buffer);
			d += 64 - (s->len & 63);
			s->len += 64 - (s->len & 63);
			len -= 64 - (s->len & 63);
		}
		while (len >= 64) {
			_sha256_update(s->h, d);
			d += 64;
			s->len += 64;
			len -= 64;
		}
		memmove(s->buffer, d, len);
	} else {
		memmove(s->buffer + (s->len & 63), data, len);
	}
	s->len += len;
}

void sha256_finish(struct sha256 *s)
{
	size_t i;

	s->buffer[s->len & 63] = 0x80;
	if ((s->len & 63) > 55) {
		memset(s->buffer + (s->len & 63) + 1, 0, 63 - (s->len & 63));
		_sha256_update(s->h, s->buffer);
		memset(s->buffer, 0, (s->len & 63) + 1);
	} else {
		memset(s->buffer + (s->len & 63) + 1, 0, 55 - (s->len & 63));
	}
	((uint32_t *)s->buffer)[14] = htonl(s->len >> 29);
	((uint32_t *)s->buffer)[15] = htonl(s->len << 3);
	_sha256_update(s->h, s->buffer);

	for (i = 0; i < sizeof(s->h) / sizeof(*s->h); i++)
		s->h[i] = htonl(s->h[i]);
}

void sha224_init(struct sha224 *s)
{
	struct sha256 *s256 = (struct sha256 *)s;
	memcpy(s256->h, (uint32_t[]){ 0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4 }, sizeof(s256->h));
	s->len = 0;
}

void sha224_update(struct sha224 *s, const void *data, size_t len)
{
	sha256_update((struct sha256 *)s, data, len);
}

void sha224_finish(struct sha224 *s)
{
	sha256_finish((struct sha256 *)s);
}

void sha256_hmac(const void *key, size_t keylen,
		const void *data, size_t datalen,
		void *h)
{
	hmac(key, keylen,
	     data, datalen,
	     (digest_init)sha256_init,
	     (digest_update)sha256_update,
	     (digest_finish)sha256_finish,
	     sizeof(struct sha256),
	     sizeof(((struct sha256 *)0)->buffer),
	     sizeof(((struct sha256 *)0)->h),
	     (ptrdiff_t)&((struct sha256 *)0)->buffer,
	     (ptrdiff_t)&((struct sha256 *)0)->h,
	     h);
}

void sha224_hmac(const void *key, size_t keylen,
		const void *data, size_t datalen,
		void *h)
{
	hmac(key, keylen,
	     data, datalen,
	     (digest_init)sha224_init,
	     (digest_update)sha224_update,
	     (digest_finish)sha224_finish,
	     sizeof(struct sha224),
	     sizeof(((struct sha224 *)0)->buffer),
	     sizeof(((struct sha224 *)0)->h),
	     (ptrdiff_t)&((struct sha224 *)0)->buffer,
	     (ptrdiff_t)&((struct sha224 *)0)->h,
	     h);
}
