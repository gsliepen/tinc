dnl  lz4.m4: Tinc autoconf integration for the LZ4 codec.
dnl  Copyright 2015 Darik Horn <dajhorn@vanadac.com>.
dnl
dnl  This program is free software; you can redistribute it and/or modify
dnl  it under the terms of the GNU General Public License as published by
dnl  the Free Software Foundation; either version 2 of the License, or
dnl  (at your option) any later version.
dnl
dnl  This program is distributed in the hope that it will be useful,
dnl  but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl  GNU General Public License for more details.
dnl
dnl  You should have received a copy of the GNU General Public License along
dnl  with this program; if not, write to the Free Software Foundation, Inc.,
dnl  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


AC_DEFUN([tinc_LZ4], [

  AC_ARG_ENABLE([lz4],
    AS_HELP_STRING([--disable-lz4], [disable lz4 compression support]))

  AC_ARG_ENABLE([lz4-builtin],
    AS_HELP_STRING([--disable-lz4-builtin], [do not use lz4 builtin]))

  AS_IF([test "x$enable_lz4" != "xno"], [
    AC_DEFINE(HAVE_LZ4, 1, [enable lz4 compression support])

    AC_ARG_WITH(lz4,
      AS_HELP_STRING([--with-lz4=DIR], [lz4 shared library prefix (eg: /usr/local)]),
      [lz4="$withval"
       CPPFLAGS="$CPPFLAGS-I$withval/include"
       LDFLAGS="$LDFLAGS -L$withval/lib"]
    )

    AC_ARG_WITH(lz4-include,
      AS_HELP_STRING([--with-lz4-include=DIR], [lz4 shared header directory]),
      [lz4_include="$withval"
       CPPFLAGS="$CPPFLAGS -I$withval"]
    )

    AC_ARG_WITH(lz4-lib,
      AS_HELP_STRING([--with-lz4-lib=DIR], [lz4 shared object directory]),
      [lz4_lib="$withval"
       LDFLAGS="$LDFLAGS -L$withval"]
    )

    dnl First we check the system copy of the library
    AS_IF([test "x$enable_lz4_builtin" != 'xyes'], [
      AC_CHECK_HEADERS(lz4.h, [
        AC_CHECK_LIB(lz4, LZ4_compress_fast_extState,
          [lz4_header='<lz4.h>'
           LIBS="$LIBS -llz4"])
      ])
    ])

    dnl If it was not found or is too old, fallback to the built-in copy
    AS_IF([test "x$enable_lz4_builtin" != 'xno' -a "x$lz4_header" = 'x'], [
      lz4_header='"lib/lz4/lz4.h"'
      lz4_builtin=1
      AC_DEFINE(HAVE_LZ4_BUILTIN, 1, [Enable lz4 builtin.])
    ])

    dnl If the first one failed and the second one is disabled, there's nothing more we can do
    AS_IF([test "x$lz4_header" = 'x'], [
      AC_MSG_ERROR("lz4 library was not found and fallback to builtin is disabled.");
    ])

  ])

  AC_DEFINE_UNQUOTED(LZ4_H, [$lz4_header], [Location of lz4.h])

  AM_CONDITIONAL([CONFIGURE_LZ4_BUILTIN], [test "x$lz4_builtin" = 'x1'])

])
