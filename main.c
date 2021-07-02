#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <inttypes.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/stat.h>

#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#include "tiny-AES-c/aes.h"
#include "arg.h"
#include "util.h"

#define SECRET_DB_PATH ".local/share/totp"
#define SECRET_DB_FILE "secrets.db"
#define SECRET_DB_NEW_SUFFIX ".new"

char *argv0;

enum digest {
	DIGEST_SHA1 = 0,
	DIGEST_SHA224,
	DIGEST_SHA256,
	DIGEST_SHA384,
	DIGEST_SHA512,
};

static const char *digest_names[] = {
	"SHA1",
	"SHA224",
	"SHA256",
	"SHA384",
	"SHA512",
};

static void (*digest_hmacs[])(const void *key, size_t keylen,
		const void *data, size_t datalen,
		void *h) = {
	sha1_hmac,
	sha224_hmac,
	sha256_hmac,
	sha384_hmac,
	sha512_hmac,
};

static size_t digest_sizes[] = {
	SHA1_HASHSIZE,
	SHA224_HASHSIZE,
	SHA256_HASHSIZE,
	SHA384_HASHSIZE,
	SHA512_HASHSIZE,
};

uint8_t get_digest(const char *s, size_t len)
{
	size_t i;

	for (i = 0; i < sizeof(digest_names) / sizeof(*digest_names); i++)
		if (!strncmp(s, digest_names[i], len) &&
		    !digest_names[i][len])
			return i;
	
	fprintf(stderr, "Unknown digest \"%.*s\", assuming %s\n", 
		(int)len, s, digest_names[DIGEST_SHA1]);
	return DIGEST_SHA1;
}

void print_base32(const uint8_t *buffer, size_t len)
{
	const char *chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	uint16_t v = 0;
	size_t b = 0;

	while (len--) {
		v = v << 8 | *buffer++;
		b += 8;
		while (b >= 5) {
			printf("%c", chars[(v >> (b - 5)) & 31]);
			b -= 5;
		}
	}
	if (b)
		printf("%c", chars[(v << (5 - b)) & 31]);
}

char *_if_prefix(char *s, const char *prefix, size_t prefixlen)
{
	if (strncmp(s, prefix, prefixlen))
		return NULL;
	return s + prefixlen;
}

#define if_prefix(s, p) _if_prefix(s, p, sizeof(p) - 1)

struct header {
	uint8_t magic[4];
	uint8_t version;
};

bool verify_db(int fd, struct AES_ctx *c)
{
	uint8_t rbuf[AES_BLOCKLEN];
	int r;
	size_t rused = 0;
	struct header *h;

	while ((r = read(fd, rbuf + rused, sizeof(rbuf) - rused)) > 0)
		rused += r;

	if (rused < sizeof(rbuf))
		return false;

	AES_CBC_decrypt_buffer(c, rbuf, sizeof(rbuf));
	h = (struct header *)(rbuf + rbuf[0] % (sizeof(rbuf) - sizeof(*h) - 1) + 1);

	if (h->magic[0] != 'T' ||
	    h->magic[1] != 'O' ||
	    h->magic[2] != 'T' ||
	    h->magic[3] != 'P' ||
	    h->version != 1)
		croak("Secret database decryption failed, check passphrase");

	return true;
}

void write_header(int fd, struct AES_ctx *c)
{
	uint8_t wbuf[AES_BLOCKLEN];
	int w;
	size_t written = 0;
	size_t i;
	struct header *h;

	for (i = 0; i < sizeof(wbuf); i++)
		wbuf[i] = rand();

	h = (struct header *)(wbuf + wbuf[0] % (sizeof(wbuf) - sizeof(*h) - 1) + 1);

	h->magic[0] = 'T';
	h->magic[1] = 'O';
	h->magic[2] = 'T';
	h->magic[3] = 'P';
	h->version = 1;

	AES_CBC_encrypt_buffer(c, wbuf, sizeof(wbuf));

	while (written < sizeof(wbuf) && (w = write(fd, wbuf + written, sizeof(wbuf) - written)) > 0)
		written += w;
}

struct totpkey {
	uint64_t t0;
	uint8_t digest;
	uint8_t digits;
	uint8_t period;
	uint8_t keylen;
	uint8_t desclen;
	uint8_t issuerlen;
	uint8_t filler1;
	uint8_t filler2;
};

void read_keys(int fd, struct AES_ctx *c,
	       void (*key_cb)(uint8_t digest,
			      uint8_t digits,
			      uint8_t period, 
			      time_t t0,
			      const uint8_t *key, size_t keylen,
			      const char *desc, size_t desclen,
			      const char *issuer, size_t issuerlen,
			      void *data),
	       void *cb_data)
{
	uint8_t decbuf[512];
	uint8_t rbuf[AES_BLOCKLEN];
	size_t dused = 0;
	size_t rused = 0;
	int r;

	while ((r = read(fd, rbuf + rused, sizeof(rbuf) - rused)) > 0) {
		struct totpkey *kh = (struct totpkey *)decbuf;
		if ((rused += r) < sizeof(rbuf))
			continue;
		AES_CBC_decrypt_buffer(c, rbuf, sizeof(rbuf));
		if (dused + sizeof(rbuf) >= sizeof(decbuf))
			break;
		memcpy(decbuf + dused, rbuf, sizeof(rbuf));
		rused = 0;
		dused += sizeof(rbuf);

		if (dused < sizeof(*kh) +
		    kh->keylen + kh->desclen + kh->issuerlen)
			continue;

		key_cb(kh->digest,
		       kh->digits,
		       kh->period,
		       _ntohll(kh->t0),
		       decbuf + sizeof(*kh), kh->keylen,
		       (const char *)(decbuf + sizeof(*kh) + kh->keylen),
		       kh->desclen,
		       (const char *)(decbuf + sizeof(*kh) + kh->keylen + kh->desclen),
		       kh->issuerlen,
		       cb_data);
		dused = 0;
	}
}

int write_key(int fd, struct AES_ctx *c,
	      uint8_t digest,
	      uint8_t digits,
	      uint8_t period,
	      time_t t0,
	      const uint8_t *key, size_t keylen,
	      const char *desc, size_t desclen,
	      const char *issuer, size_t issuerlen)
{
	size_t ksz = sizeof(struct totpkey) + keylen + desclen + issuerlen;
	size_t i;
	int w;

	ksz += AES_BLOCKLEN - 1 - ((ksz - 1) % AES_BLOCKLEN);

	if (keylen > UINT8_MAX || desclen > UINT8_MAX)
		return -EINVAL;

	uint8_t buffer[ksz];
	memcpy(buffer, &(struct totpkey){
	       .t0 = _htonll(t0),
	       .digest = digest,
	       .digits = digits,
	       .period = period,
	       .keylen = keylen,
	       .desclen = desclen,
	       .issuerlen = issuerlen }, sizeof(struct totpkey));
	memcpy(buffer + sizeof(struct totpkey), key, keylen);
	memcpy(buffer + sizeof(struct totpkey) + keylen, desc, desclen);
	memcpy(buffer + sizeof(struct totpkey) + keylen + desclen, issuer, issuerlen);
	memset(buffer + sizeof(struct totpkey) + keylen + desclen + issuerlen, 0,
	       ksz - sizeof(struct totpkey) - keylen - desclen - issuerlen);

	for (i = 0; i < ksz; i += AES_BLOCKLEN)
		AES_CBC_encrypt_buffer(c, buffer + i, AES_BLOCKLEN);
	i = 0;

	while ((w = write(fd, buffer + i, ksz - i)) > 0)
		i += w;

	if (w < 0)
		return -errno;
	return i != ksz;
}

void print_key(uint8_t digest,
	       uint8_t digits,
	       uint8_t period,
	       time_t t0,
	       const uint8_t *key, size_t keylen,
	       const char *desc, size_t desclen,
	       const char *issuer, size_t issuerlen,
	       void *data)
{
	(void)digest;
	(void)digits;
	(void)period;
	(void)key;
	(void)keylen;
	(void)issuer;
	(void)issuerlen;
	(void)t0;

	(void)data;

	printf("%.*s by %.*s\n", (int)desclen, desc, (int)issuerlen, issuer);
}

static void print_uriencode(const char *buf, size_t len, bool getarg)
{
	const char *escape = ":/@+% &?";
	while (len && *buf) {
		size_t pass = strncspn(buf, len, escape);
		printf("%.*s", (int)pass, buf);
		buf += pass;
		len -= pass;

		while (len && *buf && strchr(escape, *buf)) {
			if (*buf == ' ' && getarg)
				printf("+");
			else
				printf("%%%02" PRIx8, *(uint8_t *)buf);
			buf++;
			len--;
		}
	}
}

void print_keyuri(uint8_t digest,
		  uint8_t digits,
		  uint8_t period,
		  time_t t0,
		  const uint8_t *key, size_t keylen,
		  const char *desc, size_t desclen,
		  const char *issuer, size_t issuerlen,
		  void *data)
{
	(void)t0;
	(void)data;
	printf("otpauth://totp/");
	print_uriencode(desc, desclen, false);
	printf("?secret=");
	print_base32(key, keylen);
	if (issuerlen) {
		printf("&issuer=");
		print_uriencode(issuer, issuerlen, true);
	}
	printf("&algorithm=%s&digits=%" PRIu8 "&period=%" PRIu8 "\n",
	       digest_names[digest],
	       digits,
	       period);
}

struct generate_data {
	const char *filter;
	bool found;
};

void generate_token(uint8_t digest,
		    uint8_t digits,
		    uint8_t period,
		    time_t t0,
		    const uint8_t *key, size_t keylen,
		    const char *desc, size_t desclen,
		    const char *issuer, size_t issuerlen,
		    void *data)
{
	struct generate_data *d = data;
	uint32_t modulo = 1;
	uint8_t i;
	char descbuf[desclen + 1];

	(void)issuer;
	(void)issuerlen;

	memcpy(descbuf, desc, desclen);
	descbuf[desclen] = '\0';

	if (fnmatch(d->filter, descbuf, FNM_NOESCAPE))
		return;

	d->found = true;
	for (i = 0; i < digits; i++)
		modulo *= 10;

	printf("%0*" PRIu32 "\n", (int)digits,
	       totp(key, keylen, time(NULL), period, t0, digest_hmacs[digest], digest_sizes[digest]) % modulo);
}

struct write_filter_data {
	int fd;
	const char *filter;
	struct AES_ctx *c;
};

void write_filter_key(uint8_t digest,
		      uint8_t digits,
		      uint8_t period,
		      time_t t0,
		      const uint8_t *key, size_t keylen,
		      const char *desc, size_t desclen,
		      const char *issuer, size_t issuerlen,
		      void *data)
{
	struct write_filter_data *d = data;

	if (d->filter) {
		char descbuf[desclen + 1];

		memcpy(descbuf, desc, desclen);
		descbuf[desclen] = '\0';

		if (!fnmatch(d->filter, descbuf, FNM_NOESCAPE))
			return;
	}

	write_key(d->fd, d->c, digest, digits, period, t0,
		  key, keylen,
		  desc, desclen,
		  issuer, issuerlen);
}

enum cmd {
	CMD_NONE,
	CMD_TOK,
	CMD_LIST,
	CMD_ADD,
	CMD_DEL,
	CMD_EXP
};

void usage()
{
	fprintf(stderr,
		"Usage: totp [OPTIONS]\n"
		"-l\tlist known secrets\n"
		"-a <uri>\tadd uri to secrets\n"
		"-d <filter>\tremove secrets matching filter\n"
		"-t <filter>\tgenerate tokens for secrets matching filter\n"
		"-e\texport secrets\n");
	exit(1);
}

static inline char dehex(const char *s)
{
	if ((*s < '0' ||
	     (*s > '9' && (*s & ~0x20) < 'A') ||
	     (*s & ~0x20) > 'F') ||
	    (s[1] < '0' ||
	     (s[1] > '9' && (s[1] & ~0x20) < 'A') ||
	     (s[1] & ~0x20) > 'F'))
		return '?';
	return (*s < 'A' ? *s - '0' : (*s & ~0x20) - 'A' + 10) << 4 |
		(s[1] < 'A' ? s[1] - '0' : (s[1] & ~0x20) - 'A' + 10);
}

static size_t uridecode(char *buf, size_t len, bool getarg)
{
	char *w = buf;
	const char *r = buf;

	while (r - buf < (ptrdiff_t)len) {
		if (*r == '%') {
			if (r - buf + 2 >= (ptrdiff_t)len)
				break;
			*w++ = dehex(++r);
			r += 2;
		} else if (getarg && *r == '+') {
			*w++ = ' ';
			r++;
		} else
			*w++ = *r++;
	}

	return w - buf;
}

static void setecho(bool echo)
{
	struct termios tio;
	if (tcgetattr(STDIN_FILENO, &tio))
		return;
	if (echo)
		tio.c_lflag |= ECHO;
	else
		tio.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &tio);
}

int main(int argc, char *argv[])
{
	int fd;
	int r;
	struct sha1 d;
	enum cmd cmd = CMD_NONE;
	char *totpuri;
	const char *key = NULL;
	const char *keyfile = NULL;
	const char *keyquery = NULL;
	char *secretfile = NULL;
	char *newsecretfile = NULL;
	bool free_secretfile = true;
	uint8_t keybuf[AES_KEYLEN + AES_BLOCKLEN];
	size_t keylen = 0;
	struct generate_data gd = { NULL, false };
	char *t;

	ARGBEGIN {
		case 'l':
			cmd = CMD_LIST;
			break;
		case 'a':
			cmd = CMD_ADD;
			totpuri = EARGF(usage());
			break;
		case 'd':
			cmd = CMD_DEL;
			keyquery = EARGF(usage());
			break;
		case 't':
			cmd = CMD_TOK;
			keyquery = EARGF(usage());
			break;
		case 'e':
			cmd = CMD_EXP;
			break;
		case 'k':
			key = EARGF(usage());
			break;
		case 'K':
			keyfile = EARGF(usage());
			break;
		case 'f':
			secretfile = EARGF(usage());
			free_secretfile = false;
			break;
		default:
			usage();
			break;

	} ARGEND

	if (cmd == CMD_NONE && !argc)
		usage();

	sha1_init(&d);

	if (key) {
		sha1_update(&d, key, strlen(key));
	} else {
		size_t l = 0;
		if (keyfile && strcmp(keyfile, "-")) {
			fd = open(keyfile, O_RDONLY);
		} else {
			fd = STDIN_FILENO;

			if (!keyfile) {
				fprintf(stderr, "Enter passphrase: ");
				setecho(false);
			}
		}

		while ((r = read(fd, d.buffer + l,
				 sizeof(d.buffer) - l)) > 0) {
			size_t ll = strncspn((const char *)d.buffer + l, r, "\r\n");

			if (ll < (size_t)r) {
				l += ll;
				break;
			}

			l += r;
			if (l < sizeof(d.buffer))
				continue;
			sha1_update(&d, d.buffer, sizeof(d.buffer));
			l = 0;
		}

		if (l)
			sha1_update(&d, d.buffer, l);

		if (!keyfile) {
			fprintf(stderr, "\n");
			setecho(true);
		} else if (strcmp(keyfile, "-")) {
			close(fd);
		}
	}

	sha1_finish(&d);

	while (keylen + sizeof(d.h) < sizeof(keybuf)) {
		memcpy(keybuf + keylen, d.h, sizeof(d.h));
		memcpy(d.buffer, d.h, sizeof(d.h));
		sha1_init(&d);
		sha1_update(&d, d.buffer, sizeof(d.h)); 
		sha1_finish(&d);
		keylen += sizeof(d.h);
	}
	memcpy(keybuf + keylen, d.h, sizeof(keybuf) - keylen);

	struct AES_ctx c;
	AES_init_ctx_iv(&c,
			(uint8_t *)keybuf, (uint8_t *)keybuf + AES_KEYLEN);

	struct AES_ctx wc;
	AES_init_ctx_iv(&wc,
			(uint8_t *)keybuf, (uint8_t *)keybuf + AES_KEYLEN);

	int wfd;

	srand(time(NULL));

	if (!secretfile) {
		const char *home = getenv("HOME");
		secretfile = malloc(strlen(home) + sizeof(SECRET_DB_PATH) + sizeof(SECRET_DB_FILE) + 1);
		sprintf(secretfile, "%s/%s/%s", home, SECRET_DB_PATH, SECRET_DB_FILE);
	}

	newsecretfile = malloc(strlen(secretfile) + sizeof(SECRET_DB_NEW_SUFFIX));
	sprintf(newsecretfile, "%s%s", secretfile, SECRET_DB_NEW_SUFFIX);

	for (t = strtok(secretfile + 1, "/"); (t = strtok(NULL, "/")); ) {
		if (mkdir(secretfile, 0700) && errno != EEXIST)
			croak("Could not create secret db dir: %s", strerror(errno));
		t[-1] = '/';
	}

	switch (cmd) {
		case CMD_LIST:
			free(newsecretfile);
			fd = open(secretfile, O_RDONLY);
			if (free_secretfile)
				free(secretfile);
			if (fd < 0)
				break;
			if (!verify_db(fd, &c))
				croak("Unable to open database, check passphrase");
			read_keys(fd, &c, print_key, NULL);
			close(fd);
			break;

		case CMD_ADD: {
			size_t kl = 0;
			size_t dl = 0;
			char *i;
			char *key;
			char *desc;
			uint8_t digest = DIGEST_SHA1;
			uint8_t digits = 6;
			uint8_t period = 30;
			uint8_t issuerlen = 0;
			time_t t0 = 0;
			char *issuer;

			if (!(desc = if_prefix(totpuri, "otpauth://totp/")))
				usage();

			i = strchr(desc, '?');
			if (!i)
				usage();

			dl = uridecode(desc, i - desc, false);

			while (*i++) {
				char *v;
				if ((v = if_prefix(i, "secret="))) {
					i = v + strcspn(v, "&");
					kl = debase32(key = v, i - v);
				} else if ((v = if_prefix(i, "digits="))) {
					digits = strtoul(v, &i, 10);
				} else if ((v = if_prefix(i, "period="))) {
					period = strtoul(v, &i, 10);
				} else if ((v = if_prefix(i, "issuer="))) {
					i = v + strcspn(v, "&");
					issuerlen = uridecode(issuer = v, i - v, true);
				} else if ((v = if_prefix(i, "algorithm="))) {
					i = v + strcspn(v, "&");
					digest = get_digest(v, i - v);
				} else {
					i += strcspn(i, "&");
				}
			}

			fd = open(secretfile, O_RDONLY, 0600);
			if (fd >= 0)
				verify_db(fd, &c);

			wfd = open(newsecretfile,
				   O_WRONLY | O_TRUNC | O_CREAT, 0600);
			write_header(wfd, &wc);
			if (fd >= 0) {
				read_keys(fd, &c, write_filter_key,
					  &(struct write_filter_data){
					  	.fd = wfd, .c = &wc });
				close(fd);
			}
			write_key(wfd, &wc,
				  digest, digits, period, t0,
				  (uint8_t *)key, kl, desc, dl,
				  issuer, issuerlen);
			close(wfd);

			rename(newsecretfile, secretfile);
			free(newsecretfile);
			free(secretfile);

			break;
		}

		case CMD_NONE:
			keyquery = argv[0];
			/* fall-through */
		case CMD_TOK:
			free(newsecretfile);
			fd = open(secretfile, O_RDONLY);
			free(secretfile);
			if (fd >= 0) {
				verify_db(fd, &c);
				gd.filter = keyquery;
				read_keys(fd, &c, generate_token, &gd);
				close(fd);
			}
			if (!gd.found)
				croak("No secrets matching filter found");
			break;

		case CMD_DEL: {
			fd = open(secretfile, O_RDONLY);
			if (fd < 0)
				exit(1);
			wfd = open(newsecretfile,
				   O_WRONLY | O_TRUNC | O_CREAT, 0600);
			verify_db(fd, &c);
			write_header(wfd, &wc);
			read_keys(fd, &c, write_filter_key,
				  &(struct write_filter_data){
				  	.fd = wfd, .filter = keyquery,
					.c = &wc
				  });
			close(wfd);
			close(fd);
			rename(newsecretfile, secretfile);
			free(newsecretfile);
			free(secretfile);
			break;

		case CMD_EXP:
			free(newsecretfile);
			fd = open(secretfile, O_RDONLY);
			free(secretfile);
			if (fd < 0)
				break;
			verify_db(fd, &c);
			read_keys(fd, &c, print_keyuri, NULL);
			close(fd);
			break;
		}
	}

	return 0;
}
