EXTRA_DIST = 

if ENABLE_EXT_DNS_LOG
INCLUDE_EXT_DNS_LOG=-DENABLE_EXT_DNS_LOG
endif

if ENABLE_POLL_SUPPORT
INCLUDE_EXT_DNS_POLL=-DEXT_DNS_HAVE_POLL=1
endif

if ENABLE_EPOLL_SUPPORT
INCLUDE_EXT_DNS_EPOLL=-DEXT_DNS_HAVE_EPOLL=1
endif

if DEFAULT_EPOLL
INCLUDE_DEFAULT_EPOLL=-DDEFAULT_EPOLL 
endif

if DEFAULT_POLL
INCLUDE_DEFAULT_POLL=-DDEFAULT_POLL 
endif

INCLUDES = $(compiler_options) -I$(top_srcdir) -D__COMPILING_EXT_DNS__ -D__axl_disable_broken_bool_def__  \
	$(AXL_CFLAGS) $(INCLUDE_EXT_DNS_LOG) $(PTHREAD_CFLAGS) \
	-DVERSION=\""$(EXT_DNS_VERSION)"\" \
	-DPACKAGE_DTD_DIR=\""$(datadir)"\" \
	-DPACKAGE_TOP_DIR=\""$(top_srcdir)"\" $(INCLUDE_EXT_DNS_POLL) $(INCLUDE_EXT_DNS_EPOLL) $(INCLUDE_DEFAULT_EPOLL) $(INCLUDE_DEFAULT_POLL)

libext_dns_includedir = $(includedir)/ext-dns

lib_LTLIBRARIES = libext-dns.la

libext_dns_la_SOURCES =	\
	ext-dns.c \
	ext-dns-ctx.c

libext_dns_include_HEADERS = \
	ext-dns.h \
	ext-dns-types.h \
	ext-dns-private.h \
	ext-dns-ctx.h

libext_dns_la_LIBADD = \
	$(AXL_LIBS) $(PTHREAD_LIBS) $(ADDITIONAL_LIBS)

libext_dns_la_LDFLAGS = -no-undefined -export-symbols-regex '^(ext_dns|__ext_dns|_ext_dns).*'

libext-dns.def: update-def

update-def:
	echo "EXPORTS" > libext-dns.def
	cat .libs/libext-dns.exp | grep -v __ext_dns >> libext-dns.def
