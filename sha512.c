#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <arpa/inet.h>

#include "sha512.h"
#include "util.h"

static inline uint64_t rotr64(uint64_t x, uint8_t n)
{
	return x >> n | x << (64 - n);
}

static inline void add8(uint64_t *dest, const uint64_t *src)
{
	size_t i;

	for (i = 0; i < 8; i++)
		dest[i] += src[i];
}

static inline void rotmod8(uint64_t *a, uint64_t k, uint64_t w)
{
	uint64_t t1 = a[7] + (rotr64(a[4], 14) ^ rotr64(a[4], 18) ^ rotr64(a[4], 41)) + ((a[4] & a[5]) ^ (~a[4] & a[6])) + k + w;
	uint64_t t2 = (rotr64(a[0], 28) ^ rotr64(a[0], 34) ^ rotr64(a[0], 39)) + ((a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]));

	memmove(a + 1, a, 7 * sizeof(*a));

	a[4] += t1;
	a[0] = t1 + t2;
}

static inline uint64_t getnw(uint64_t *w, size_t i)
{
	return w[i & 15] +=
		(rotr64(w[(i + 1) & 15], 1) ^ rotr64(w[(i + 1) & 15], 8) ^ (w[(i + 1) & 15] >> 7)) +
		w[(i + 9) & 15] +
		(rotr64(w[(i + 14) & 15], 19) ^ rotr64(w[(i + 14) & 15], 61) ^ (w[(i + 14) & 15] >> 6));
}

void sha512_init(struct sha512 *s)
{
	memcpy(s->h, (uint64_t[]){
			0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 
			0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 
			}, sizeof(s->h));
	s->len = 0;
}

static inline void _sha512_update(uint64_t *h, const void *data)
{
	const uint64_t k[] = {
		0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
		0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
		0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
		0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
		0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
		0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
		0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
		0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
		0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
		0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
		0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
		0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
		0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
		0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
		0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
	}; 
	const uint64_t *d = data;

	uint64_t w[16];
	size_t i;

	uint64_t wr[8];
	memcpy(wr, h, sizeof(wr));

	for (i = 0; i < sizeof(w) / sizeof(*w); i++)
		rotmod8(wr, k[i], w[i] = _ntohll(d[i]));

	for (; i < sizeof(k) / sizeof(*k); i++)
		rotmod8(wr, k[i], getnw(w, i));

	add8(h, wr);
}

void sha512_update(struct sha512 *s, const void *data, size_t len)
{
	if ((s->len & 127) + len >= 128) {
		const char *d = data;
		if (s->len & 128) {
			memcpy(s->buffer + (s->len & 127), d, 128 - (s->len & 127));
			_sha512_update(s->h, s->buffer);
			d += 128 - (s->len & 127);
			s->len += 128 - (s->len & 127);
			len -= 128 - (s->len & 127);
		}
		while (len >= 128) {
			_sha512_update(s->h, d);
			d += 128;
			s->len += 128;
			len -= 128;
		}
		memmove(s->buffer, d, len);
	} else {
		memmove(s->buffer + (s->len & 127), data, len);
	}
	s->len += len;
}

void sha512_finish(struct sha512 *s)
{
	size_t i;

	s->buffer[s->len & 127] = 0x80;
	if ((s->len & 127) > 111) {
		memset(s->buffer + (s->len & 127) + 1, 0, 127 - (s->len & 127));
		_sha512_update(s->h, s->buffer);
		memset(s->buffer, 0, (s->len & 127) + 1);
	} else {
		memset(s->buffer + (s->len & 127) + 1, 0, 119 - (s->len & 127));
	}
	((uint64_t *)s->buffer)[15] = _htonll(s->len << 3);
	_sha512_update(s->h, s->buffer);

	for (i = 0; i < sizeof(s->h) / sizeof(*s->h); i++)
		s->h[i] = _htonll(s->h[i]);
}

void sha384_init(struct sha384 *s)
{
	struct sha512 *s5 = (struct sha512 *)s;
	memcpy(s5->h, (uint64_t[]){
			0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 
			0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
	       }, sizeof(s5->h));
	s5->len = 0;
}

void sha384_update(struct sha384 *s, const void *data, size_t len)
{
	sha512_update((struct sha512 *)s, data, len);
}

void sha384_finish(struct sha384 *s)
{
	sha512_finish((struct sha512 *)s);
}

void sha512_hmac(const void *key, size_t keylen,
		const void *data, size_t datalen,
		void *h)
{
	hmac(key, keylen,
	     data, datalen,
	     (digest_init)sha512_init,
	     (digest_update)sha512_update,
	     (digest_finish)sha512_finish,
	     sizeof(struct sha512),
	     sizeof(((struct sha512 *)0)->buffer),
	     sizeof(((struct sha512 *)0)->h),
	     (ptrdiff_t)&((struct sha512 *)0)->buffer,
	     (ptrdiff_t)&((struct sha512 *)0)->h,
	     h);
}

void sha384_hmac(const void *key, size_t keylen,
		const void *data, size_t datalen,
		void *h)
{
	hmac(key, keylen,
	     data, datalen,
	     (digest_init)sha384_init,
	     (digest_update)sha384_update,
	     (digest_finish)sha384_finish,
	     sizeof(struct sha384),
	     sizeof(((struct sha384 *)0)->buffer),
	     sizeof(((struct sha384 *)0)->h),
	     (ptrdiff_t)&((struct sha384 *)0)->buffer,
	     (ptrdiff_t)&((struct sha384 *)0)->h,
	     h);
}
