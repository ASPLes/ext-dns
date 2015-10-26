if ENABLE_EXT_DNS_DOC
EXT_DNS_DOC_DIR = doc
endif

SUBDIRS = src test query server $(EXT_DNS_DOC_DIR)
EXTRA_DIST = VERSION
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ext-dns.pc

all-local: update-defs

update-defs:
	cd src; make update-def; cd ..
