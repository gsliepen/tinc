dnl Check to find the lzo headers/libraries

AC_DEFUN([tinc_LZO],
[
  AC_ARG_WITH(lzo,
    AS_HELP_STRING([--with-lzo=DIR], [lzo base directory, or:]),
    [lzo="$withval"
     CPPFLAGS="$CPPFLAGS -I$withval/include"
     LDFLAGS="$LDFLAGS -L$withval/lib"]
  )

  AC_ARG_WITH(lzo-include,
    AS_HELP_STRING([--with-lzo-include=DIR], [lzo headers directory]),
    [lzo_include="$withval"
     CPPFLAGS="$CPPFLAGS -I$withval"]
  )

  AC_ARG_WITH(lzo-lib,
    AS_HELP_STRING([--with-lzo-lib=DIR], [lzo library directory]),
    [lzo_lib="$withval"
     LDFLAGS="$LDFLAGS -L$withval"]
  )

  AC_CHECK_HEADERS(lzo1x.h,
    [],
    [AC_MSG_ERROR("lzo header files not found."); break]
  )

  AC_CHECK_LIB(lzo, lzo1x_1_compress,
    [LIBS="$LIBS -llzo"],
    [AC_MSG_ERROR("lzo libraries not found.")]
  )
])
