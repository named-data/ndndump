#####################################################################
# libpcap libraries
#####################################################################
#   AX_LIBPCAP([ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
#
# DESCRIPTION
#
#	Will use pcap-config from $PATH unless user specifically defined path to
#	pcap-config
#
#   This macro calls:
#
#     AC_SUBST(LIBPCAP_CFLAGS) / AC_SUBST(LIBPCAP_LIBS)
#
#   And calls ACTION-IF-FOUND or ACTION-IF-NOT-FOUND appropriately
#
# LICENSE
#	Copyright (c) 2011 Alexander Afanasyev <alexander.afanasyev@ucla.edu>
#
#   Based on libvirt's configure.ac
#
#	Copying and distribution of this file, with or without modification, are
#	permitted in any medium without royalty provided the copyright notice
#	and this notice are preserved. This file is offered as-is, without any
#	warranty.

AC_DEFUN([AX_LIBPCAP],
[
  AC_ARG_WITH([libpcap],
    [AS_HELP_STRING([--with-libpcap=DIR],
      [path to pcap-config binary])],
    [
      case "$withval" in
      "" | y | ye | yes | n | no)
        AC_MSG_ERROR([Invalid --with-libpcap value])
        ;;
      *)
        LIBPCAP_CONFIG="$withval/pcap-config"
        ;;
      esac
    ],
    [
      LIBPCAP_CONFIG="pcap-config"
    ]
  )

  dnl pcap lib
  LIBPCAP_REQUIRED=$1
  succeeded=no

  AC_MSG_CHECKING(libpcap using $LIBPCAP_CONFIG)
 
  if ! $LIBPCAP_CONFIG --libs > /dev/null 2>&1 ; then
    AC_MSG_RESULT([no])
  else
    LIBPCAP_LIBS="`$LIBPCAP_CONFIG --libs`"
    LIBPCAP_CFLAGS="`$LIBPCAP_CONFIG --cflags`"
    succeeded=yes
    AC_MSG_RESULT([yes])
  fi

  if test "$succeeded" != "yes" ; then
    # execute ACTION-IF-NOT-FOUND (if present):
    ifelse([$2], , :, [$2])
  else
    AC_SUBST(LIBPCAP_LIBS)
    AC_SUBST(LIBPCAP_CFLAGS)
    # execute ACTION-IF-FOUND (if present):
    ifelse([$1], , :, [$1])
  fi

])

