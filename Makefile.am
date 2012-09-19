SUBDIRS = src test query server
EXTRA_DIST = VERSION
# pkgconfigdir = $(libdir)/pkgconfig
# pkgconfig_DATA = ext-dns-1.1.pc

all-local: update-defs

update-defs:
	cd src; make update-def; cd ..
