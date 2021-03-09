#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <arpa/inet.h>

#include "sha1.h"
#include "util.h"

static inline uint32_t rotl32(uint32_t x, uint8_t n)
{
	return x << n | x >> (32 - n);
}

static inline void add5(uint32_t *dest, const uint32_t *src)
{
	size_t i;

	for (i = 0; i < 5; i++)
		dest[i] += src[i];
}

static inline void rotmod5(uint32_t *a, uint32_t f, uint32_t k, uint32_t w)
{
	uint32_t t = rotl32(a[0], 5) + f + a[4] + k + w;
	memmove(a + 1, a, 4 * sizeof(*a));
	a[2] = rotl32(a[2], 30);
	a[0] = t;
}

static inline uint32_t getnw(uint32_t *w, size_t i)
{
	return w[i & 15] = rotl32(w[(i + 13) & 15] ^ w[(i + 8) & 15] ^ w[(i + 2) & 15] ^ w[i & 15], 1);
}

void sha1_init(struct sha1 *s)
{
	memcpy(s->h, (uint32_t[]){ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 }, 5 * sizeof(*s->h));
	s->len = 0;
}

static inline void _sha1_update(uint32_t *h, const void *data)
{
	const uint32_t k[4] = { 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 }; 
	const uint32_t *d = data;

	uint32_t w[16];
	size_t i;

	uint32_t wr[5];
	memcpy(wr, h, sizeof(wr));

	for (i = 0; i < 16; i++)
		rotmod5(wr, (wr[1] & wr[2]) | (~wr[1] & wr[3]), k[0], w[i] = ntohl(d[i]));
	for (; i < 20; i++)
		rotmod5(wr, (wr[1] & wr[2]) | (~wr[1] & wr[3]), k[0], getnw(w, i));
	for (; i < 40; i++)
		rotmod5(wr, wr[1] ^ wr[2] ^ wr[3], k[1], getnw(w, i));
	for (; i < 60; i++)
		rotmod5(wr, (wr[1] & wr[2]) | (wr[1] & wr[3]) | (wr[2] & wr[3]), k[2], getnw(w, i));
	for (; i < 80; i++)
		rotmod5(wr, wr[1] ^ wr[2] ^ wr[3], k[3], getnw(w, i));

	add5(h, wr);
}

void sha1_update(struct sha1 *s, const void *data, size_t len)
{
	if ((s->len & 63) + len >= 64) {
		const char *d = data;
		if (s->len & 63) {
			memcpy((uint8_t *)s->buffer + (s->len & 63), d, 64 - (s->len & 63));
			_sha1_update(s->h, s->buffer);
			d += 64 - (s->len & 63);
			s->len += 64 - (s->len & 63);
			len -= 64 - (s->len & 63);
		}
		while (len >= 64) {
			_sha1_update(s->h, d);
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

void sha1_finish(struct sha1 *s)
{
	size_t i;

	((uint8_t *)s->buffer)[s->len & 63] = 0x80;
	if ((s->len & 63) > 55) {
		memset((uint8_t *)s->buffer + (s->len & 63) + 1, 0, 63 - (s->len & 63));
		_sha1_update(s->h, s->buffer);
		memset(s->buffer, 0, (s->len & 63) + 1);
	} else {
		memset((uint8_t *)s->buffer + (s->len & 63) + 1, 0, 55 - (s->len & 63));
	}
	s->buffer[14] = htonl(s->len >> 29);
	s->buffer[15] = htonl(s->len << 3);
	_sha1_update(s->h, s->buffer);

	for (i = 0; i < sizeof(s->h) / sizeof(*s->h); i++)
		s->h[i] = htonl(s->h[i]);
}

void sha1_hmac(const void *key, size_t keylen,
	       const void *data, size_t datalen,
	       void *h)
{
	hmac(key, keylen,
	     data, datalen,
	     (digest_init)sha1_init,
	     (digest_update)sha1_update,
	     (digest_finish)sha1_finish,
	     sizeof(struct sha1),
	     sizeof(((struct sha1 *)0)->buffer),
	     sizeof(((struct sha1 *)0)->h),
	     (ptrdiff_t)&((struct sha1 *)0)->buffer,
	     (ptrdiff_t)&((struct sha1 *)0)->h,
	     h);
}
