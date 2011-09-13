#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.62)
AC_INIT(ndndump, 0.1, zhenkai@cs.ucla.edu)
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_SRCDIR([src/headers.h])

AM_INIT_AUTOMAKE([-Wall])

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_CXX_C_O
AX_BOOST_BASE([1.40],
  [AX_BOOST_REGEX],
  [AC_MSG_ERROR([Required boost libraries not found])])

# Checks for libraries.
AX_CCNX([0.4.0],,[AC_MSG_ERROR([Required CCNx library not found])])
AX_CHECK_OPENSSL(,[AC_MSG_ERROR([Required OpenSSL not found])])
AX_LIBPCAP(,[AC_MSG_ERROR([Required libpcap library not found])])

AC_OUTPUT(Makefile src/Makefile)
