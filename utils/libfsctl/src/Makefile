top_srcdir = ../../..
top_builddir = ../../..

BUILD_SRCS = $(wildcard *.c)
BUILD_OBJS = $(patsubst %.c,%.o,$(BUILD_SRCS))

include $(top_builddir)/build/rules.mk

LINKNAME = libfsctl.so
SONAME = $(LINKNAME).$(MAJOR_VERSION)
REALNAME = $(LINKNAME).$(MAJOR_VERSION).$(MINOR_VERSION)

BUILD_BINS += $(REALNAME)
BUILD_TARGETS += $(REALNAME)
CLEAN_FILES = $(LINKNAME) $(SONAME) $(REALNAME)

INCLUDES += -I.
INCLUDES += -I$(top_srcdir)/include
INCLUDES += -I$(top_srcdir)/../common/include

LDLIBS += -lpthread
LDLIBS += -L$(top_builddir)/../utils/debug_log -ltmdebug

$(REALNAME): $(BUILD_OBJS)
	$(CC) -shared -Wl,-soname,$(SONAME) -o $@ $^ $(LDLIBS)
	ln -sf $(REALNAME) $(SONAME)
	ln -sf $(SONAME) $(LINKNAME)
