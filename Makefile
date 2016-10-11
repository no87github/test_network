#########################################################################
# Special variables which should not be exported                        #
#########################################################################
unexport top_builddir
unexport INCLUDES
unexport SUBDIRS
unexport BUILD_SUBDIRS
unexport BUILD_TARGETS
unexport BUILD_BINS
unexport BUILD_OBJS
unexport CLEAN_SUBDIRS
unexport CLEAN_TARGETS
unexport CLEAN_FILES
unexport INSTALL_SUBDIRS
unexport INSTALL_TARGETS

top_builddir =
INCLUDES =
SUBDIRS =
BUILD_SUBDIRS =
BUILD_TARGETS =
BUILD_BINS =
BUILD_OBJS =
CLEAN_SUBDIRS =
CLEAN_TARGETS =
CLEAN_FILES =
INSTALL_SUBDIRS =
INSTALL_TARGETS =

#########################################################################
# Modules Platform                                                      #
#########################################################################

top_builddir = .
SUBDIRS += utils
SUBDIRS += src
SUBDIRS += src/unitest
BUILD_OBJS = prebuild
INSTALL_TARGETS = postbuild
include $(top_builddir)/build/rules.mk

PATTERN_FILES = lpt* ssaptn.* tmblack.* tmwhite.*

PRJPATH = $(OUTPUT_ROOT)/opt/TrendMicro/$(PRJNAME)
PRJPATH_SUBDIRS = engine pattern bin lib etc

CONFIG_FILES += filescan.conf
CONFIG_FILES += spyware_exclude_vscan

VAR_REPLACE_SH = $(top_builddir)/../../scripts_build/var_replace.sh
#CLEAN_FILES = $(PRJPATH)/bin/$(CODENAME) $(PRJPATH)/bin/$(CODENAME).sh $(PRJPATH)/bin/fsctl $(PRJPATH)/lib/libvscan.so* $(PRJPATH)/lib/libswissknife.so* $(PRJPATH)/lib/libtm_text.so* $(PRJPATH)/lib/libtpool.so* $(PRJPATH)/lib/libmsg_utils.so* $(PRJPATH)/lib/libfsctl.so* $(PRJPATH)/engine/$(VSAPI_LIBNAME) $(PRJPATH)/etc/filescan.conf* $(PRJPATH)/etc/filescan.text* $(PRJPATH)/etc/spyware_exclude_vscan* $(PRJPATH)/pattern/*

TOP_DIR = ../../..
PO     = fs2.po
POKEYS = -k_ -kN_
POPATH ?= $(TOP_DIR)/src/po
POSRCS = common/include/*.h include/*.h src/*.c 

ifeq ($(ARCH),x86_64)
	LIB=lib64
	ENGINE=engine
else
	LIB=lib
	ENGINE=engine
endif

prebuild:
	@echo "[Build Options]"
	@echo "+ DATETIME=$(shell date)"
	@echo "+ PRJPATH=$(PRJPATH)"
	@echo "+ CODENAME=$(CODENAME)"
	@echo "+ ARCH=$(ARCH)"
	@echo "+ OS=$(OS)"
	@echo "+ LOCALE=$(LOCALE)"
	@echo "+ MAJOR_VERSION=$(MAJOR_VERSION)"
	@echo "+ MINOR_VERSION=$(MINOR_VERSION)"
	@echo "+ REVISION_NUMBER=$(REVISION_NUMBER)"
	@echo "+ BUILD_NUMBER=$(BUILD_NUMBER)"
	@echo "+ CROSS=$(CROSS)"
	@echo "+ CC=$(CC)"
	@echo "+ CXX=$(CXX)"
	@echo "+ LD=$(LD)"
	@echo "+ AR=$(AR)"
	@echo "+ STRIP=$(STRIP)"
	@echo "+ OBJCOPY=$(OBJCOPY)"
	@echo "+ CFLAGS=$(CFLAGS)"
	@echo "+ CPPFLAGS=$(CPPFLAGS)"
	@echo "+ LDFLAGS=$(LDFLAGS)"
	@echo


postbuild:
	# Making installation directories
	@list='$(PRJPATH_SUBDIRS)'; \
	for i in $${list}; do \
		echo "Making $(PRJPATH)/$${i}"; \
		mkdir -p "$(PRJPATH)/$${i}"; \
	done;

	@cp -pRPf conf/* $(PRJPATH)/etc/
	# Config
	@list=' $(CONFIG_FILES)'; \
	for i in $${list}; do \
		if test -f "conf/$${i}"; then \
			cp -pRPf conf/$${i} $(PRJPATH)/etc/$${i}.def; \
		fi; \
	done;

	# File Scan
	@cp -pRP utils/vscan/src/libvscan.so* $(PRJPATH)/$(LIB)/
	@cp -pRP utils/swissknife/libswissknife.so* $(PRJPATH)/$(LIB)/
	@cp -pRP utils/tpool/src/libtpool.so* $(PRJPATH)/$(LIB)/
	@cp -pRP utils/msg_utils/libmsg_utils.so* $(PRJPATH)/$(LIB)/
	@cp -pRP utils/libfsctl/src/libfsctl.so* $(PRJPATH)/$(LIB)/
ifeq ($(ARCH),x86_64)
	@install -m 755 src/$(CODENAME) $(PRJPATH)/bin/$(CODENAME)
	@cp -pRP utils/libfsctl/unittest/fsctl $(PRJPATH)/bin/
	@cp -a src/unitest/bdiff $(PRJPATH)/bin/
	@cp -a src/unitest/recv_tr $(PRJPATH)/bin/
	@cp -a src/unitest/recv_fd $(PRJPATH)/bin/
	@cp -a src/unitest/send_fd $(PRJPATH)/bin/
	# Common Modules
	@install -D -m 755 ../../../import/$(VSAPI)/$(LIB)/$(VSAPI_LIBNAME) $(PRJPATH)/$(ENGINE)/$(VSAPI_LIBNAME)
endif
	# Pattern Files
	@list='$(PATTERN_FILES)'; \
	for i in $${list}; do \
		cp -pRP ../../../import/Pattern/$${i} $(PRJPATH)/pattern/; \
	done;
	@chmod 644 $(PRJPATH)/pattern/*
	# Replace _PRJNAME_ symbol in runtime file
	@$(VAR_REPLACE_SH) $(PRJPATH)/etc/filescan.conf $(PRJPATH)/etc/filescan.conf _PRJNAME_=$(PRJNAME) _ENGINE_=$(ENGINE) _VSAPI_LIBNAME_=$(VSAPI_LIBNAME)
	@$(VAR_REPLACE_SH) $(PRJPATH)/etc/filescan.conf $(PRJPATH)/etc/filescan.conf.def _PRJNAME_=$(PRJNAME) _ENGINE_=$(ENGINE) _VSAPI_LIBNAME_=$(VSAPI_LIBNAME)
ifeq ($(ARCH),x86_64)
	# put the script to the unique path /opt/TrendMicro/MinorityReport/bin
	@$(VAR_REPLACE_SH) src/$(CODENAME).sh $(PRJPATH)/bin/$(CODENAME).sh _PRJNAME_=$(PRJNAME) _ARCH_=$(ARCH)
	@chmod 755 $(PRJPATH)/bin/$(CODENAME).sh
endif

L10N:
	xgettext --no-wrap -o $(PO) $(POKEYS) $(POSRCS)
	mkdir -p $(POPATH)
	@if [ -f $(PO) ]; then install $(PO) $(POPATH); fi
	@make -C utils L10N
