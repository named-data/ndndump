# Binary
bin_PROGRAMS = ndndump
ndndump_SOURCES = ndndump.c headers.h

ndndump_LDFLAGS = $(CCNX_LDFLAGS) $(OPENSSL_LDFLAGS)
ndndump_LDADD = $(CCNX_LIBS) $(OPENSSL_LIBS) $(LIBPCAP_LIBS)
ndndump_CFLAGS = $(CCNX_CFLAGS) $(OPENSSL_INCLUDES) $(LIBPCAP_CFLAGS)

