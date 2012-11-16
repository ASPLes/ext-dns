SUBDIRS = src test query server doc
EXTRA_DIST = VERSION
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ext-dns.pc

all-local: update-defs

update-defs:
	cd src; make update-def; cd ..
