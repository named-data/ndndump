#####################################################################
# CCNx libraries
#####################################################################
#   AX_CCNX([MINIMUM-API-VERSION], [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
#
# DESCRIPTION
#
#	If no path to the installed CCNx library is given the macro searches
#	under /usr, /usr/local, /opt and /opt/local
#
#   This macro calls:
#
#     AC_SUBST(CCNX_CFLAGS) / AC_SUBST(CCNX_LDFLAGS) / AC_SUBST(CCNX_LIBS)
#
#   And calls ACTION-IF-FOUND or ACTION-IF-NOT-FOUND appropriately
#
# LICENSE
#	Copyright (c) 2011 Alexander Afanasyev <alexander.afanasyev@ucla.edu>
#
#	Copying and distribution of this file, with or without modification, are
#	permitted in any medium without royalty provided the copyright notice
#	and this notice are preserved. This file is offered as-is, without any
#	warranty.

AC_DEFUN([AX_CCNX],
[
  AC_ARG_WITH([ccnx],
    [AS_HELP_STRING([--with-ccnx=DIR],
      [root directory for CCNx library])],
    [
      case "$withval" in
      "" | y | ye | yes | n | no)
        AC_MSG_ERROR([Invalid --with-ccnx value])
        ;;
      *)
        basedirs="$withval"
        indir="in $withval"
        ;;
      esac
    ],
    [
      basedirs="/usr /usr/local /opt /opt/local"
      indir=""
    ]
  )
 
  ccnx_lib_version_req=ifelse([$1], ,0.4.0,$1)
  ccnx_lib_version_req_major=`expr $ccnx_lib_version_req : '\([[0-9]]*\)'`
  ccnx_lib_version_req_minor=`expr $ccnx_lib_version_req : '[[0-9]]*\.\([[0-9]]*\)'`
  ccnx_lib_version_req_sub_minor=`expr $ccnx_lib_version_req : '[[0-9]]*\.[[0-9]]*\.\([[0-9]]*\)'`
  if test "x$ccnx_lib_version_req_sub_minor" = "x" ; then
    ccnx_lib_version_req_sub_minor="0"
  fi
  WANT_CCNX_VERSION=`expr $ccnx_lib_version_req_major \* 100000 \+  $ccnx_lib_version_req_minor \* 1000 \+ $ccnx_lib_version_req_sub_minor`

  AC_MSG_CHECKING(for CCNx library with API version >= $ccnx_lib_version_req $indir)
  succeeded=no
  found=false

  libsubdirs="lib64 lib"
  
  for ccnx_base_tmp in $basedirs ; do
    if test -d "$ccnx_base_tmp/include/ccn" && test -r "$ccnx_base_tmp/include/ccn"; then
      for libsubdir in $libsubdirs ; do
        if ls "$ccnx_base_tmp/$libsubdir/libccn"* >/dev/null 2>&1 ; then break; fi
      done
      CCNX_LDFLAGS="-L$ccnx_base_tmp/$libsubdir"
      CCNX_CFLAGS="-I$ccnx_base_tmp/include"
      CCNX_LIBS="-lccn"
      found=true
      break;
    fi
  done

  if ! $found; then
    AC_MSG_RESULT([no])
  else
    save_LIBS="$LIBS"
    save_LDFLAGS="$LDFLAGS"
    save_CFLAGS="$CFLAGS"
    LDFLAGS="$LDFLAGS $CCNX_LDFLAGS"
    LIBS="$CCNX_LIBS $LIBS"
    CFLAGS="$CCNX_CFLAGS $CFLAGS"

    AC_REQUIRE([AC_PROG_CC])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
        @%:@include <ccn/ccn.h>
      ]], [[
        #if CCN_API_VERSION >= $WANT_CCNX_VERSION
        // Everything is okay
        #else
        #  error CCNx API version is too old
        #endif
    ]])],[
      AC_MSG_RESULT([yes])
      succeeded=yes
    ],[
    ])

    CFLAGS="$save_CFLAGS"
    LDFLAGS="$save_LDFLAGS"
    LIBS="$save_LIBS"
  fi

  if test "$succeeded" != "yes" ; then
    # execute ACTION-IF-NOT-FOUND (if present):
    ifelse([$3], , :, [$3])
  else
    AC_SUBST(CCNX_CFLAGS)
    AC_SUBST(CCNX_LDFLAGS)
    AC_SUBST(CCNX_LIBS)
    # execute ACTION-IF-FOUND (if present):
    ifelse([$2], , :, [$2])
  fi

])

