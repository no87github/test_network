CC=gcc
CFLAGS=-g  -Wall
CFLAGS+=-I.
CFLAGS+=-I../../../../../../../import/VSAPI/include
CFLAGS+=-I../../../../common/include -I../../../../../common/include
#CFLAGS += -I../../../em_filter/include
CFLAGS+=-DUSE_PTHREAD -DLINUX -DI386 -D_GNU_SOURCE

LIBS +=-L../../src -lvscan
LIBS +=-L../../../msg_utils -lmsg_utils
LIBS +=-L../../../../../utils/glcfg/bin -lglcfg
LIBS += -L../../../../../../../import/VSAPI/lib -lvsapi
LIBS += -L../../../../../utils/debug_log  -ltmdebug
LIBS +=-lpthread
LIBS +=-ldl
LIBS += -L../../../swissknife -lswissknife
#LIBS += -L../../../../../sci/lib -lsci
#LIBS += -L../../../em_filter/src -lem_filter


all: vscan_test vscan_test_fd
vscan_test:main.o
	$(CC) -o $@ $(CFLAGS)  $^ $(LIBS)  

vscan_test_fd:main_fd.o
	$(CC) -o $@ $(CFLAGS)  $^ $(LIBS)  

.PHONY:clean
clean:
	rm -rf vscan_test vscan_test_fd *~ *.o core.*

