top_builddir = ..

SUBDIRS += swissknife
SUBDIRS += msg_utils
SUBDIRS += vscan
SUBDIRS += tpool
SUBDIRS += libfsctl

include $(top_builddir)/build/rules.mk

L10N:
	@for i in $(SUBDIRS); do \
		make -C $$i $@; \
	done

