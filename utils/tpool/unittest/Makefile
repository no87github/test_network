top_srcdir = ../../..
top_builddir = ../../..

BUILD_SRCS = $(wildcard *.c)
BUILD_OBJS = $(patsubst %.c,%.o,$(BUILD_SRCS))
BUILD_TARGETS = tpool_test
CLEAN_FILES = tpool_test $(BUILD_OBJS)

include $(top_builddir)/build/rules.mk

CPPFLAGS += -I../include
CPPFLAGS += -I$(top_srcdir)/../common/include

LDLIBS += -L$(top_builddir)/../utils/debug_log -ltmdebug
LDLIBS += -L$(top_builddir)/../utils/glcfg/bin -lglcfg
LDLIBS += -L$(top_builddir)/../utils/ixml/bin -L$(top_builddir)/../utils/ixml/bin/debug -lixml
LDLIBS += -L../src -ltpool
LDLIBS += -lpthread

tpool_test: $(BUILD_OBJS)
	$(CC) -o $@ $^ $(LDLIBS)

run:
	env LD_LIBRARY_PATH=../src:$(top_builddir)/../utils/debug_log ./tpool_test
