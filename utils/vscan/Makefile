top_builddir = ../..

SUBDIRS = src

include $(top_builddir)/build/rules.mk

TOP_DIR = ../../../../..
PO     = fs2_utils_vscan.po
POKEYS = -k_ -kN_
POPATH ?= $(TOP_DIR)/src/po
POSRCS = src/*.c src/*.h

L10N:
	xgettext --no-wrap -o $(PO) $(POKEYS) $(POSRCS)
	mkdir -p $(POPATH)
	@if [ -f $(PO) ]; then install $(PO) $(POPATH); fi


