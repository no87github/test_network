top_srcdir = ../../..
top_builddir = ../../..

BUILD_SRCS = $(wildcard *.c)
BUILD_OBJS = $(patsubst %.c,%.o,$(BUILD_SRCS))

include $(top_builddir)/build/rules.mk

LINKNAME = libvscan.so
SONAME = $(LINKNAME).$(MAJOR_VERSION)
REALNAME = $(LINKNAME).$(MAJOR_VERSION).$(MINOR_VERSION)

BUILD_BINS += $(REALNAME)
BUILD_TARGETS += $(REALNAME)
CLEAN_FILES = $(LINKNAME)* $(SONAME) $(REALNAME)

CPPFLAGS += -DUSE_TMDEBUG -DTmDebugModuleID=0x42
CPPFLAGS += -DUSE_PTHREAD

INCLUDES += -I.
INCLUDES += -I../include
INCLUDES += -I$(top_srcdir)/include
INCLUDES += -I$(top_srcdir)/common/include
INCLUDES += -I$(top_srcdir)/../common/include
INCLUDES += -I$(top_srcdir)/../../common/include
INCLUDES += -I$(top_srcdir)/utils/swissknife
INCLUDES += -I$(top_srcdir)/utils/em_filter/include
INCLUDES += -I$(top_srcdir)/../tmSyslog/include

LDLIBS += -lpthread
LDLIBS += -L$(top_builddir)/utils/msg_utils -lmsg_utils
LDLIBS += -L$(top_builddir)/utils/swissknife -lswissknife
LDLIBS += -L$(top_builddir)/../utils/debug_log -ltmdebug
LDLIBS += -L$(top_builddir)/../utils/glcfg/bin -lglcfg
LDLIBS += -L$(top_builddir)/../utils/ixml/bin -lixml
LDLIBS += -L$(top_builddir)/../tmSyslog/src -ltmsyslog

$(REALNAME): $(BUILD_OBJS)
	$(CC) -shared -Wl,-soname,$(SONAME) -o $@ $^ $(LDLIBS)
	ln -sf $(REALNAME) $(SONAME)
	ln -sf $(SONAME) $(LINKNAME)
