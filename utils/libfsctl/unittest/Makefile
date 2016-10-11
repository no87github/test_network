top_builddir = ../../..

BUILD_OBJS += $(patsubst %.c,%.o,$(shell echo *.c))
BUILD_TARGETS += fsctl
CLEAN_FILES += fsctl $(BUILD_OBJS)

include $(top_builddir)/build/rules.mk

INCLUDES += -I$(top_builddir)/include
INCLUDES += -I$(top_builddir)/common/include

LDLIBS += -L../src -lfsctl
LDLIBS += -L$(top_builddir)/../utils/debug_log -ltmdebug
LDLIBS += -L$(top_builddir)/../utils/glcfg -lglcfg
LDLIBS += -L$(top_builddir)/../utils/ixml/bin -lixml

fsctl: $(BUILD_OBJS)
#	$(CC) -o fsctl $^ -L../src -lfsctl
