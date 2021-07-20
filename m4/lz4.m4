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
    AS_HELP_STRING([--disable-lz4], [disable all lz4 compression support])
  )

  AC_ARG_ENABLE([lz4-builtin],
    AS_HELP_STRING([--disable-lz4-builtin], [required to link an lz4 library])
  )

  AC_ARG_WITH(lz4,
    AS_HELP_STRING([--with-lz4=DIR], [lz4 shared library prefix (eg: /usr/local)]),
    [lz4="$withval" CPPFLAGS="$CPPFLAGS -I$withval/include" LDFLAGS="$LDFLAGS -L$withval/lib"]
  )

  AC_ARG_WITH(lz4-include,
    AS_HELP_STRING([--with-lz4-include=DIR], [lz4 shared header directory]),
    [lz4_include="$withval" CPPFLAGS="$CPPFLAGS -I$withval"]
  )

  AC_ARG_WITH(lz4-lib,
    AS_HELP_STRING([--with-lz4-lib=DIR], [lz4 shared object directory]),
    [lz4_lib="$withval" LDFLAGS="$LDFLAGS -L$withval"]
  )

  dnl Calling this early prevents autoconf lint.
  AM_CONDITIONAL([CONFIGURE_LZ4_BUILTIN], [test "$enable_lz4_builtin" != 'no'])

  AS_IF([test "$enable_lz4" != 'no' -a "$enable_lz4_builtin" != 'no' ], [
    AC_DEFINE(HAVE_LZ4, 1, [Enable lz4 support.])
    AC_DEFINE(HAVE_LZ4_BUILTIN, 1, [Enable lz4 builtin.])
    AC_DEFINE(HAVE_LZ4_STATE, 1, [Enable lz4 external state features.])
    AC_DEFINE(
      [LZ4_compress_shim(a, b, c, d)],
      [LZ4_compress_fast_extState(lz4_wrkmem, a, b, c, d, 0)],
      [This is the best interface for the lz4 builtin.]
    )
  ],[
    AS_IF([test "$enable_lz4" != 'no'], [
      AC_CHECK_HEADERS(lz4.h, [
        AC_DEFINE(LZ4_H, [<lz4.h>], [Location of lz4.h])

        AC_CHECK_LIB(lz4, LZ4_compress_fast_extState, [
          LIBS="$LIBS -llz4"
          AC_DEFINE(HAVE_LZ4, 1, [Enable lz4 compression support.])
          AC_DEFINE(HAVE_LZ4_STATE, 1, [Enable lz4 external state features.])
          AC_DEFINE(
            [LZ4_compress_shim(a, b, c, d)],
            [LZ4_compress_fast_extState(lz4_wrkmem, a, b, c, d, 0)],
            [The lz4-r129 library interface.]
          )
          break
        ])

        AC_CHECK_LIB(lz4, LZ4_compress_default, [
          LIBS="$LIBS -llz4"
          AC_DEFINE(HAVE_LZ4, 1, [Enable lz4 compression support.])
          AC_DEFINE(
            [LZ4_compress_shim(a, b, c, d)],
            [LZ4_compress_default(a, b, c, d)],
            [The lz4-r128 library interface.]
          )
          break
        ])

        AC_CHECK_LIB(lz4, LZ4_compress_limitedOutput, [
          LIBS="$LIBS -llz4"
          AC_DEFINE(HAVE_LZ4, 1, [Enable lz4 compression support.])
          AC_DEFINE(
            [LZ4_compress_shim(a, b, c, d)],
            [LZ4_compress_limitedOutput(a, b, c, d)],
            [The lz4-r59 library interface.]
          )
          AC_MSG_WARN("Using deprecated lz4-r59 interface.")
          break
        ])

      ],[
        AC_MSG_ERROR("lz4.h header file not found.")
        break
      ])

    ])

  ])

])
