include $(top_builddir)/build/build.conf
include $(top_builddir)/../../build.conf
include $(top_builddir)/../../cross.$(ARCH).conf
CROSS ?=
CC = $(CROSS)gcc
CXX ?= $(CROSS)g++
LD ?= $(CROSS)ld
AR ?= $(CROSS)ar
STRIP ?= $(CROSS)strip
OBJCOPY ?= $(CROSS)objcopy
PROJECT_RUNTIME_PATH ?= /opt/TrendMicro/$(PRJNAME)
#VSAPI = VSAPI_PLUS
VSAPI = ATSE

ifeq ($(VSAPI),ATSE)
VSAPI_LIBNAME=libatse.so
else
VSAPI_LIBNAME=libvsapi.so
endif

PO_LIST = fs2.po fs2_utils_libfsctl.po fs2_utils_msg_utils.po fs2_utils_swissknife.po fs2_utils_tpool.po fs2_utils_vscan.po

ifdef DEBUG
CFLAGS += -g3 -ggdb
CPPFLAGS += -UNDEBUG -DDEBUG
else
CFLAGS += -O2 -g3 -ggdb
CPPFLAGS += -DNDEBUG
endif

INCLUDES += -I$(top_srcdir)/../../../import/$(VSAPI)/include

CFLAGS += -fPIC -pipe -Wall -Wshadow -Wswitch-default -Wswitch-enum -Wcast-align -Wformat=2 #-Wextra
#CFLAGS += -Wstrict-prototypes -Wmissing-prototypes
CPPFLAGS += -D_GNU_SOURCE
ifeq ($(ARCH), x86_64)
CPPFLAGS += -DLNXAMD64
else
CPPFLAGS += -DLINUX -DI386
endif
CPPFLAGS += $(INCLUDES)
CPPFLAGS += -DPROJECT_RUNTIME_PATH=\"$(PROJECT_RUNTIME_PATH)\"
CPPFLAGS += -DUSE_$(VSAPI) -DVSAPI_LIBNAME=$(VSAPI_LIBNAME) -DVSAPI_LIBNAME_STR=\"$(VSAPI_LIBNAME)\"

.PHONY: all
all: $(BUILD_OBJS)
	@target=$@; \
	list='$(BUILD_SUBDIRS) $(SUBDIRS)'; \
	for i in $${list}; do \
		if test -d "$${i}"; then \
			echo "Making $${target} in $${i}"; \
			($(MAKE) -C $${i} $${target}) || exit 1; \
		fi; \
	done;
	@if test -n "$(BUILD_TARGETS)"; then \
		$(MAKE) $(BUILD_TARGETS); \
	fi;

.PHONY: debug
debug:
	$(MAKE) DEBUG=1 $(all)

.PHONY: clean 
clean:
	@target=$@; \
	list='$(CLEAN_SUBDIRS) $(SUBDIRS)'; \
	for i in $${list}; do \
		if test -d "$${i}"; then \
			echo "Making $${target} in $${i}"; \
			($(MAKE) -C $${i} $${target}) || exit 1; \
		fi; \
	done;
	@if test -n "$(CLEAN_TARGETS)"; then \
		$(MAKE) $(CLEAN_TARGETS); \
	fi;
	@$(RM) $(BUILD_OBJS) $(BUILD_BINS) $(CLEAN_FILES) *.dbg *~ .dep
	@$(RM) $(PO_LIST)

.PHONY: install
install:
	@target=$@; \
	list='$(INSTALL_SUBDIRS) $(SUBDIRS)'; \
	for i in $${list}; do \
		if test -d "$${i}"; then \
			echo "Making $${target} in $${i}"; \
			($(MAKE) -C $${i} $${target}) || exit 1; \
		fi; \
	done;
	@if test -n "$(INSTALL_TARGETS)"; then \
		$(MAKE) $(INSTALL_TARGETS); \
	fi;

.dep: $(BUILD_SRCS)
	@if test -n "$^"; then \
		$(CC) $(CPPFLAGS) -MM $^ > .dep 2>/dev/null || echo > .dep; \
	fi;

-include .dep
