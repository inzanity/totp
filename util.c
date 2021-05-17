#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "util.h"

void xormem(void *a, const void *b, size_t len)
{
	uint8_t *wa = a;
	const uint8_t *rb = b;
	while (len--)
		*wa++ ^= *rb++;
}

void hmac(const void *key, size_t keylen,
	  const void *data, size_t datalen,
	  digest_init init,
	  digest_update update,
	  digest_finish finish,
	  size_t ctxsz,
	  size_t blocksz,
	  size_t digestsz,
	  ptrdiff_t buf_off,
	  ptrdiff_t digest_off,
	  void *h)
{
	char s[ctxsz];
	char s2[ctxsz];

	init(s);
	memset(s + buf_off, 0x36, blocksz);
	if (keylen > blocksz) {
		init(s2);
		update(s2, key, keylen);
		finish(s2);
		xormem(s + buf_off, s2 + digest_off, digestsz);
	} else {
		xormem(s + buf_off, key, keylen);
	}

	update(s, s + buf_off, blocksz);
	update(s, data, datalen);
	finish(s);

	memset(s2 + buf_off, 0x5c, blocksz);
	if (keylen > blocksz)
		xormem(s2 + buf_off, s2 + digest_off, digestsz);
	else
		xormem(s2 + buf_off, key, keylen);
	init(s2);
	update(s2, s2 + buf_off, blocksz);
	update(s2, s + digest_off, digestsz);
	finish(s2);
	memcpy(h, s2 + digest_off, digestsz);
}

uint32_t hotp(const void *key, size_t keylen,
	 const void *counter, size_t counterlen,
	 void (*hmac_f)(const void *key, size_t keylen,
			const void *data, size_t datalen,
			void *h), size_t hshsz)
{
	uint8_t h[hshsz];

	hmac_f(key, keylen, counter, counterlen, h);

	return ntohl(*(uint32_t *)&((uint8_t *)h)[h[hshsz - 1] & 0xf]) &
		0x7fffffff;
}

uint32_t totp(const void *key, size_t keylen,
	      time_t t1, uint8_t period,
	      time_t t0,
	      void (*hmac_f)(const void *key, size_t keylen,
			   const void *data, size_t datalen,
			   void *h), size_t hshsz)
{
	uint64_t tv = _htonll((t1 - t0) / period);

	return hotp(key, keylen, &tv, sizeof(tv), hmac_f, hshsz);
}

size_t strncspn(const char *s, size_t l, const char *c)
{
	size_t disallowed[256 / 8 / sizeof(size_t)] = { 0 };
	const unsigned char *u = (const unsigned char *)c;

	if (!*c)
		return 0;
	for (u = (const unsigned char *)c;
	     *u && (disallowed[*u / (8 * sizeof(*disallowed))] |= 1ULL << (*u % (8 * sizeof(*disallowed))));
	     u++);
	disallowed[0] |= 1;
	for (u = (const unsigned char *)s;
	     l-- && !(disallowed[*u / (8 * sizeof(*disallowed))] & 1ULL << (*u % (8 * sizeof(*disallowed))));
	     u++);

	return (const char *)u - s;
}

size_t strnspn(const char *s, size_t l, const char *c)
{
	size_t allowed[256 / 8 / sizeof(size_t)] = { 0 };
	const unsigned char *u = (const unsigned char *)c;

	if (!*c)
		return 0;
	for (u = (const unsigned char *)c;
	     *u && (allowed[*u / (8 * sizeof(*allowed))] |= 1ULL << (*u % (8 * sizeof(*allowed))));
	     u++);
	for (u = (const unsigned char *)s;
	     l-- && (allowed[*u / (8 * sizeof(*allowed))] & 1ULL << (*u % (8 * sizeof(*allowed))));
	     u++);

	return (const char *)u - s;
}

void croak(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fputs("\n", stderr);

	exit(1);
}

size_t debase32(char *buffer, size_t len)
{
	uint8_t *wp = (uint8_t *)buffer;
	const uint8_t *rp = (const uint8_t *)buffer;
	uint16_t v = 0;
	size_t b = 0;

	for (rp = (uint8_t *)buffer; (char *)rp - buffer < (ptrdiff_t)len && *rp && *rp != '='; rp++) {
		uint8_t c = *rp >= 'A' ? *rp - 'A' : *rp - '2' + 26;
		v = v << 5 | c;
		b += 5;
		if (b >= 8) {
			*wp++ = (v >> (b & 7)) & 255;
			b -= 8;
		}
	}
	return (char *)wp - buffer;
}
