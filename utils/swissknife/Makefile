top_srcdir = ../..
top_builddir = ../..

BUILD_SRCS = $(wildcard sk_*.c)
BUILD_OBJS = $(patsubst %.c,%.o,$(BUILD_SRCS))

include $(top_builddir)/build/rules.mk

LINKNAME = libswissknife.so
SONAME = $(LINKNAME).$(MAJOR_VERSION)
REALNAME = $(LINKNAME).$(MAJOR_VERSION).$(MINOR_VERSION)

BUILD_BINS += $(REALNAME)
BUILD_TARGETS += $(REALNAME)
CLEAN_FILES = $(LINKNAME) $(SONAME) $(REALNAME) $(patsubst %.c,%,$(wildcard test_sk_*.c))

CPPFLAGS += -DTmDebugModuleID=0x40
# Enable this to use lock()/unlock() to gurantee atomic operation. Turn it on
# will definitely decrease overall performance.
#CPPFLAGS += -DSK_ATOMIC_COUNTER
# Enable this to use read() and write() to simulate sendfile()
CPPFLAGS += -DSK_NO_SENDFILE

ifdef DEBUG
CPPFLAGS += -DSK_DEBUG_BLOCK
CPPFLAGS += -DSK_DEBUG_BUFFER
CPPFLAGS += -DSK_DEBUG_CONFIG
CPPFLAGS += -DSK_DEBUG_COUNTER
CPPFLAGS += -DSK_DEBUG_DSET
CPPFLAGS += -DSK_DEBUG_IO
CPPFLAGS += -DSK_DEBUG_LIST
CPPFLAGS += -DSK_DEBUG_POOL
CPPFLAGS += -DSK_DEBUG_SCFG
CPPFLAGS += -DSK_DEBUG_STRING
CPPFLAGS += -DSK_DEBUG_STRSET
CPPFLAGS += -DSK_DEBUG_SYSINFO
CPPFLAGS += -DSK_DEBUG_TALLOCATOR
CPPFLAGS += -DSK_DEBUG_TOKENIZER
CPPFLAGS += -DSK_DEBUG_TEXT
CPPFLAGS += -DSK_DEBUG_WORKTIME
CPPFLAGS += -DSK_DEBUG_WRAPPER
endif # DEBUG

INCLUDES += -I.
INCLUDES += -I$(top_srcdir)/common/include
INCLUDES += -I$(top_srcdir)/../common/include
INCLUDES += -I$(top_srcdir)/../sci/include
INCLUDES += -I$(top_srcdir)/../utils/glcfg
INCLUDES += -I$(top_srcdir)/../utils/urltran/include

#LDLIBS += -L$(top_builddir)/../sci/lib -lsci
LDLIBS += -L$(top_builddir)/../utils/debug_log -ltmdebug
LDLIBS += -L$(top_builddir)/../utils/glcfg/bin -lglcfg
LDLIBS += -L$(top_builddir)/../utils/ixml/bin -lixml
LDLIBS += -L$(top_builddir)/../utils/urltran/src -lurltran
LDLIBS += -lpthread

TOP_DIR = ../../../../..
PO     = fs2_utils_swissknife.po
POKEYS = -k_ -kN_
POPATH ?= $(TOP_DIR)/src/po
POSRCS = *.c *.h

$(REALNAME): $(BUILD_OBJS)
	$(CC) -shared -Wl,-soname,$(SONAME) -o $@ $^ $(LDLIBS)
	ln -sf $(REALNAME) $(SONAME)
	ln -sf $(SONAME) $(LINKNAME)

test_sk_%: test_sk_%.o libswissknife.so
	$(CC) $(LDFLAGS) -o $@ $< -L. -lswissknife $(LDLIBS)

L10N:
	xgettext --no-wrap -o $(PO) $(POKEYS) $(POSRCS)
	mkdir -p $(POPATH)
	@if [ -f $(PO) ]; then install $(PO) $(POPATH); fi
