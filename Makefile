CFLAGS = -g -W -Wall -std=c99
AES_CFLAGS += -DECB=0 -DCBC=1 -DCTR=0 -DAES256=1
SOURCES = sha1.c sha256.c sha512.c tiny-AES-c/aes.c main.c util.c
OBJS = ${SOURCES:.c=.o}
TEST_SOURCES = sha1.c sha256.c sha512.c util.c test.c
TEST_OBJS = ${TEST_SOURCES:.c=.o}

all: totp

totp: ${OBJS}
	${CC} -o $@ ${OBJS} ${LDFLAGS}

test: ${TEST_OBJS};
	${CC} -o $@ ${TEST_OBJS} ${LDFLAGS}

.c.o:
	${CC} -c $< -o $@ ${CFLAGS} ${AES_CFLAGS}

clean:
	rm ${OBJS}
