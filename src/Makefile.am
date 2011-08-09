# Binary
bin_PROGRAMS = ndndump
ndndump_SOURCES = ndndump.cc headers.h \
ccnb-decoder.h ccnb-decoder.cc \
print-helper.h print-helper.cc

ndndump_LDFLAGS = $(CCNX_LDFLAGS) $(OPENSSL_LDFLAGS)
ndndump_LDADD = $(CCNX_LIBS) $(OPENSSL_LIBS) $(LIBPCAP_LIBS)
ndndump_CFLAGS = $(CCNX_CFLAGS) $(OPENSSL_INCLUDES) $(LIBPCAP_CFLAGS)

