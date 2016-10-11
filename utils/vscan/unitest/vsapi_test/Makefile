CC=gcc
CFLAGS=-g  -Wall
CFLAGS+=-I.
CFLAGS+=-I../../include/vsapi
CFLAGS+=-I../../../../common/include
CFLAGS+=-DUSE_PTHREAD -DLINUX -DI386 -D_GNU_SOURCE
LDFLAGS=-L../../lib/vsapi -lvsapi
LDFLAGS+=-lpthread
all: vsapi_test
vsapi_test:main.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS)  -o $@

.PHONY:clean
clean:
	rm -rf vsapi_test *~ *.o

