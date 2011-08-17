# Binary
bin_PROGRAMS = ndndump
ndndump_SOURCES = ndndump.cc headers.h \
ccnb-print-xml.h ccnb-print-xml.cc \
print-helper.h print-helper.cc \
ccnx-decoding-helper.h ccnx-decoding-helper.cc

ndndump_LDFLAGS = $(CCNX_LDFLAGS) $(OPENSSL_LDFLAGS) $(BOOST_LDFLAGS)
ndndump_LDADD = $(CCNX_LIBS) $(OPENSSL_LIBS) $(LIBPCAP_LIBS) $(BOOST_REGEX_LIB)
ndndump_CPPFLAGS = $(CCNX_CFLAGS) $(OPENSSL_INCLUDES) $(LIBPCAP_CFLAGS) $(BOOST_CPPFLAGS)
