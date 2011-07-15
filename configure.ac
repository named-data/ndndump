#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.62)
AC_INIT(ndndump, 0.1, zhenkai@cs.ucla.edu)
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([src/headers.h])

AM_INIT_AUTOMAKE([-Wall])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([pcap.h ccn/ccn.h ])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gettimeofday inet_ntoa memset])

AC_OUTPUT(Makefile src/Makefile)
