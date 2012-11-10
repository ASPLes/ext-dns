if ENABLE_EXT_DNS_LOG
INCLUDE_EXT_DNS_LOG=-DENABLE_EXT_DNS_LOG
endif

EXTRA_DIST =

noinst_PROGRAMS = ext-dns-regression-listener ext-dns-regression-client \
	ext-dns-simple-listener

INCLUDES = -I$(top_srcdir)/src  $(AXL_CFLAGS)  $(PTHREAD_CFLAGS) \
	$(compiler_options) -D__axl_disable_broken_bool_def__   \
        -DVERSION=\""$(EXT_DNS_VERSION)"\" $(INCLUDE_EXT_DNS_POLL) $(INCLUDE_EXT_DNS_EPOLL) $(INCLUDE_EXT_DNS_LOG) 

LIBS            = $(AXL_LIBS) $(PTHREAD_LIBS) $(ADDITIONAL_LIBS)

ext_dns_regression_listener_SOURCES        = ext-dns-regression-listener.c
ext_dns_regression_listener_LDADD          = $(LIBS) $(top_builddir)/src/libext-dns.la 

ext_dns_simple_listener_SOURCES        = ext-dns-simple-listener.c
ext_dns_simple_listener_LDADD          = $(LIBS) $(top_builddir)/src/libext-dns.la 

ext_dns_regression_client_SOURCES        = ext-dns-regression-client.c
ext_dns_regression_client_LDADD          = $(LIBS) $(top_builddir)/src/libext-dns.la 

