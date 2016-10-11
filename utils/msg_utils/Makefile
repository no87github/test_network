top_srcdir = ../..
top_builddir = ../..

BUILD_SRCS = $(wildcard *.c)
BUILD_OBJS = $(patsubst %.c,%.o,$(BUILD_SRCS))

include $(top_builddir)/build/rules.mk

LINKNAME = libmsg_utils.so
SONAME = $(LINKNAME).$(MAJOR_VERSION)
REALNAME = $(LINKNAME).$(MAJOR_VERSION).$(MINOR_VERSION)

BUILD_BINS += $(REALNAME)
BUILD_TARGETS += $(REALNAME)
CLEAN_FILES = $(LINKNAME) $(SONAME) $(REALNAME)

CPPFLAGS += -DUSE_TMDEBUG -DTmDebugModuleID=0x43

INCLUDES += -I.
INCLUDES += -I$(top_srcdir)/include
INCLUDES += -I$(top_srcdir)/common/include
INCLUDES += -I$(top_srcdir)/../common/include
INCLUDES += -I$(top_srcdir)/../quarantine/include
INCLUDES += -I$(top_srcdir)/utils/swissknife
INCLUDES += -I$(top_srcdir)/utils/em_filter/include

LDLIBS += -L$(top_builddir)/../utils/debug_log -ltmdebug
LDLIBS += -L$(top_builddir)/utils/swissknife

TOP_DIR = ../../../../..
PO     = fs2_utils_msg_utils.po
POKEYS = -k_ -kN_
POPATH ?= $(TOP_DIR)/src/po
POSRCS = *.c *.h

$(REALNAME): $(BUILD_OBJS)
	$(CC) -shared -Wl,-soname,$(SONAME) -o $@ $^ $(LDLIBS)
	ln -sf $(REALNAME) $(SONAME)
	ln -sf $(SONAME) $(LINKNAME)

L10N:
	xgettext --no-wrap -o $(PO) $(POKEYS) $(POSRCS)
	mkdir -p $(POPATH)
	@if [ -f $(PO) ]; then install $(PO) $(POPATH); fi
