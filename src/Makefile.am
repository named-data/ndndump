# Binary
bin_PROGRAMS = ndndump
ndndump_SOURCES = ndndump.cc headers.h \
ccnb-print-xml.h ccnb-print-xml.cc \
ccnb-print-plain.h ccnb-print-plain.cc \
print-helper.h print-helper.cc \
ccnb-parser/syntax-tree/ccnb-parser-attr.cc \
ccnb-parser/syntax-tree/ccnb-parser-blob.cc \
ccnb-parser/syntax-tree/ccnb-parser-block.cc \
ccnb-parser/syntax-tree/ccnb-parser-dattr.cc \
ccnb-parser/syntax-tree/ccnb-parser-dtag.cc \
ccnb-parser/syntax-tree/ccnb-parser-ext.cc \
ccnb-parser/syntax-tree/ccnb-parser-tag.cc \
ccnb-parser/syntax-tree/ccnb-parser-udata.cc \
ccnb-parser/visitors/ccnb-parser-depth-first-visitor.cc \
ccnb-parser/visitors/ccnb-parser-no-argu-depth-first-visitor.cc \
ccnb-parser/visitors/ccnb-parser-non-negative-integer-visitor.cc \
ccnb-parser/visitors/ccnb-parser-string-visitor.cc \
ccnb-parser/visitors/ccnb-parser-void-depth-first-visitor.cc \
ccnb-parser/visitors/ccnb-parser-void-no-argu-depth-first-visitor.cc \
ccnb-parser/visitors/ccnb-parser-name-components-visitor.cc \
ccnb-parser/visitors/ccnb-parser-name-combiner.cc \
ccnb-parser/visitors/ccnb-parser-timestamp-visitor.cc 

#ccnb-parser/visitors/ccnb-parser-nonce-visitor.cc 

ndndump_LDFLAGS = $(CCNX_LDFLAGS) $(OPENSSL_LDFLAGS) $(BOOST_LDFLAGS)
ndndump_LDADD = $(CCNX_LIBS) $(OPENSSL_LIBS) $(LIBPCAP_LIBS) $(BOOST_REGEX_LIB)
ndndump_CPPFLAGS = -Iccnb-parser $(CCNX_CFLAGS) $(OPENSSL_INCLUDES) $(LIBPCAP_CFLAGS) $(BOOST_CPPFLAGS)
