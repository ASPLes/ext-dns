if ENABLE_EXT_DNS_LOG
INCLUDE_EXT_DNS_LOG=-DENABLE_EXT_DNS_LOG
endif

EXTRA_DIST = ext-dns.example.conf

bin_PROGRAMS = ext-dnsd

INCLUDES = -I$(top_srcdir)/src  $(AXL_CFLAGS)  $(PTHREAD_CFLAGS) $(EXARG_FLAGS) \
	$(compiler_options) -D__axl_disable_broken_bool_def__   \
        -DVERSION=\""$(EXT_DNS_VERSION)"\" $(INCLUDE_EXT_DNS_POLL) $(INCLUDE_EXT_DNS_EPOLL) $(INCLUDE_EXT_DNS_LOG) 

LIBS            = $(AXL_LIBS) $(PTHREAD_LIBS) $(ADDITIONAL_LIBS)

ext_dnsd_SOURCES        = main.c exarg.c exarg.h
ext_dnsd_LDADD          = $(LIBS) $(top_builddir)/src/libext-dns.la 

# copy exarg dependency to not force people to download a library with
# two files
exarg.h exarg.c: 
	test -e exarg.h || cp ~/af-arch/libexarg/src/exarg.h .
	test -e exarg.c || cp ~/af-arch/libexarg/src/exarg.c .


