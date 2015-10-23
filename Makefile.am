if ENABLE_EXT_DNS_DOC
EXT_DNS_DOR_DIR = doc
endif

SUBDIRS = src test query server $(ENABLE_EXT_DNS_DOC)
EXTRA_DIST = VERSION
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ext-dns.pc

all-local: update-defs

update-defs:
	cd src; make update-def; cd ..
