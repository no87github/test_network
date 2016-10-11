top_builddir = ../..

SUBDIRS = src unittest

include $(top_builddir)/build/rules.mk

TOP_DIR = ../../../../..
PO     = fs2_utils_tpool.po
POKEYS = -k_ -kN_
POPATH ?= $(TOP_DIR)/src/po
POSRCS = src/*.c src/*.h include/*.h

L10N:
	xgettext --no-wrap -o $(PO) $(POKEYS) $(POSRCS)
	mkdir -p $(POPATH)
	@if [ -f $(PO) ]; then install $(PO) $(POPATH); fi
