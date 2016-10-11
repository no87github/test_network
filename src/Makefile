top_srcdir = ..
top_builddir = ..

FILESCAN = filescan
#OBJ = mp_entry.o fsctl_vscan.o fsctl_config.o fsctl_svr.o fs_vlog.o ${FILESCAN}.o
FSCTL = fsctl
CTLOBJ = libfsctl.o $(FSCTL).o

BUILD_SRCS += $(wildcard *.c)
BUILD_OBJS += $(patsubst %.c,%.o,$(BUILD_SRCS))
BUILD_TARGETS += $(FILESCAN)
CLEAN_FILES = $(FILESCAN) $(patsubst %.c,%,$(BUILD_SRCS)) mtrace.txt

include $(top_builddir)/build/rules.mk

CPPFLAGS += -DUSE_TMDEBUG -DTmDebugModuleID=0x02
CPPFLAGS += -D__LITTLE_ENDIAN_BITFIELD

INCLUDES += -I.
INCLUDES += -I$(top_srcdir)/../common/include
INCLUDES += -I$(top_srcdir)/include
INCLUDES += -I$(top_srcdir)/common/include
INCLUDES += -I$(top_srcdir)/utils/swissknife
INCLUDES += -I$(top_srcdir)/../tmSyslog/include
#INCLUDES += -I$(top_srcdir)/../../driver/fpga/vsapi2
INCLUDES += -I$(top_srcdir)/../../driver/ncit/include
INCLUDES += -I$(top_builddir)/../../system/src/openssl/include

LDLIBS += -ldl -lpthread -lrt
LDLIBS += -L$(top_builddir)/utils/swissknife -lswissknife
LDLIBS += -L$(top_builddir)/utils/msg_utils -lmsg_utils
LDLIBS += -L$(top_builddir)/utils/vscan/src -lvscan
LDLIBS += -L$(top_builddir)/../utils/debug_log -ltmdebug
LDLIBS += -L$(top_builddir)/../utils/glcfg -lglcfg
LDLIBS += -L$(top_builddir)/../utils/ixml/bin -lixml
LDLIBS += -L$(top_builddir)/../utils/urltran/src -lurltran
LDLIBS += -L$(top_builddir)/../tmSyslog/src -ltmsyslog

ifeq ($(ARCH), x86_64)
CPPFLAGS += -DLNXAMD64
else
CPPFLAGS += -DI386
CPPFLAGS += -DLINUX
endif

LDLIBS += -L$(top_builddir)/utils/tpool/src -ltpool
LDLIBS += -L$(top_builddir)/../../system/src/openssl/lib -lcrypto

ifdef DEBUG
CPPFLAGS += -DSK_DEBUG_BUFFER
CPPFLAGS += -DSK_DEBUG_STRING
endif # DEBUG

$(FILESCAN): $(BUILD_OBJS)
#	$(STRIP) $(FILESCAN)

TAGS:
	ctags -R

test: filescan
	LD_LIBRARY_PATH=/opt/TrendMicro/$(PRJNAME)/lib:/opt/TrendMicro/$(PRJNAME)/engine ./filescan -d; ../../cav/src/trigger_read VAC > tr.raw; ../../cav/src/trigger_print < tr.raw > tr.print

test_stop: filescan filescan.sh
	../../cav/src/trigger_send VAC < /dev/null; ./filescan.sh stop

test_clean:
	cat /dev/null > /var/log/filescan.log
	rm tr.raw tr.print

mtest: filescan
	LD_LIBRARY_PATH=/opt/TrendMicro/MinorityReport/lib:/opt/TrendMicro/MinorityReport/engine MALLOC_TRACE=mtrace.txt ./filescan -m; /opt/crosscompiler/skg-tool-32/i686-pc-linux-gnu/bin/mtrace ./filescan mtrace.txt
