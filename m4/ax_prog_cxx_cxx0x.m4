dnl Copyright 2010 Saleem Abdulrasool <compnerd@compnerd.org>
dnl The test program is taken verbatim from AX_CXX_COMPILE_STDCXX_0X, which is
dnl Copyright (c) 2008 Benjamin Kosnik <bkoz@redhat.com>

m4_define([CXX0X_TEST_PROGRAM],
          [AC_LANG_PROGRAM([[]],[[
template <typename T>
struct check
{
   static_assert(sizeof(int) <= sizeof(T), "not big enough");
};

typedef check<check<bool>> right_angle_brackets;

int a;
decltype(a) b;

typedef check<int> check_type;
check_type c;
check_type& cr = c;
          ]]) ])

dnl AX_PROG_CXX_CXX0X(ACTION-IF-FOUND, ACTION-IF-NOT-FOUND)
AC_DEFUN([AX_PROG_CXX_CXX0X],
         [
            AC_REQUIRE([AC_PROG_CXX])

            AC_CACHE_CHECK([if $CXX supports C++0x features without additional flags],
                           [ac_cv_cxx_compile_cxx0x_native],
                           [
                              AC_LANG_PUSH([C++])
                              AC_COMPILE_IFELSE([CXX0X_TEST_PROGRAM], [ac_cv_cxx_compile_cxx0x_native=yes], [ac_cv_cxx_compile_cxx0x_native=no])
                              AC_LANG_POP([C++])
                           ])

            AC_CACHE_CHECK([if $CXX supports C++0x features with -std=c++0x],
                           [ac_cv_cxx_compile_cxx0x_cxx],
                           [
                              AC_LANG_PUSH([C++])
                              ac_save_CXXFLAGS="$CXXFLAGS"
                              CXXFLAGS="$CXXFLAGS -std=c++0x"
                              AC_COMPILE_IFELSE([CXX0X_TEST_PROGRAM], [ac_cv_cxx_compile_cxx0x_cxx=yes], [ac_cv_cxx_compile_cxx0x_cxx=no])
                              CXXFLAGS="$ac_save_CXXFLAGS"
                              AC_LANG_POP([C++])
                           ])

            AC_CACHE_CHECK([if $CXX supports C++0x features with -std=gnu++0x],
                           [ac_cv_cxx_compile_cxx0x_gxx],
                           [
                              AC_LANG_PUSH([C++])
                              ac_save_CXXFLAGS="$CXXFLAGS"
                              CXXFLAGS="$CXXFLAGS -std=gnu++0x"
                              AC_COMPILE_IFELSE([CXX0X_TEST_PROGRAM], [ac_cv_cxx_compile_cxx0x_gxx=yes], [ac_cv_cxx_compile_cxx0x_gxx=no])
                              CXXFLAGS="$ac_save_CXXFLAGS"
                              AC_LANG_POP([C++])
                           ])

            if test "$ac_cv_cxx_compile_cxx0x_native" = yes ; then
               ac_cv_prog_cxx_cxx0x=yes
            elif test "$ac_cv_cxx_compile_cxx0x_cxx" = yes ; then
               CXXFLAGS="$CXXFLAGS -std=c++0x"
               ac_cv_prog_cxx_cxx0x=yes
            elif test "$ac_cv_cxx_compile_cxx0x_gxx" = yes ; then
               CXXFLAGS="$CXXFLAGS -std=gnu++0x"
               ac_cv_prog_cxx_cxx0x=yes
            else
               ac_cv_prog_cxx_cxx0x=no
            fi

            AS_IF([test "$ac_cv_prog_cxx_cxx0x" != no], [$1], [$2])
         ])

