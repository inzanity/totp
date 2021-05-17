#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include <arpa/inet.h>

typedef void (*digest_init)(void *c);
typedef void (*digest_update)(void *c, const void *data, size_t len);
typedef void (*digest_finish)(void *c);

void xormem(void *a, const void *b, size_t len);
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
	  void *h);

uint32_t totp(const void *key, size_t keylen,
	      time_t t1, uint8_t period,
	      time_t t0,
	      void (*hmac_f)(const void *key, size_t keylen,
			   const void *data, size_t datalen,
			   void *h), size_t hshsz);

uint32_t hotp(const void *key, size_t keylen,
	 const void *counter, size_t counterlen,
	 void (*hmac_f)(const void *key, size_t keylen,
			const void *data, size_t datalen,
			void *h), size_t hshsz);

size_t strncspn(const char *haystack, size_t haystacklen, const char *needles);

static inline uint64_t _htonll(uint64_t v)
{
	union {
		uint64_t v64;
		uint32_t v32[2];
	} rv;
	rv.v32[0] = htonl(v >> 32);
	rv.v32[1] = htonl(v & 0xffffffffU);

	return rv.v64;
}

static inline uint64_t _ntohll(uint64_t v)
{
	union {
		uint64_t v64;
		uint32_t v32[2];
	} rv;
	rv.v64 = v;

	return (uint64_t)ntohl(rv.v32[0]) << 32 | ntohl(rv.v32[1]);
}

static inline void writebeu64(uint8_t *buffer, uint64_t v)
{
	*buffer++ = v >> 56;
	*buffer++ = v >> 48;
	*buffer++ = v >> 40;
	*buffer++ = v >> 32;
	*buffer++ = v >> 24;
	*buffer++ = v >> 16;
	*buffer++ = v >> 8;
	*buffer++ = v;
}

void croak(const char *fmt, ...);
size_t debase32(char *buffer, size_t len);

#endif
