dnl Check to find the lzo headers/libraries

AC_DEFUN(tinc_LZO,
[
  tinc_ac_save_CPPFLAGS="$CPPFLAGS"

  AC_ARG_WITH(lzo-include,
    [  --with-lzo-include=DIR lzo headers directory],
    [lzo_include="$withval"
     CFLAGS="$CFLAGS -I$withval"
     CPPFLAGS="$CPPFLAGS -I$withval"]
  )

  AC_ARG_WITH(lzo-lib,
    [  --with-lzo-lib=DIR     lzo library directory],
    [lzo_lib="$withval"
     LIBS="$LIBS -L$withval"]
  )

  AC_CHECK_HEADERS(lzo1x.h,
    [],
    [AC_MSG_ERROR("lzo header files not found."); break]
  )

  CPPFLAGS="$tinc_ac_save_CPPFLAGS"

  AC_CHECK_LIB(lzo, lzo1x_1_compress,
    [LIBS="$LIBS -llzo"],
    [AC_MSG_ERROR("lzo libraries not found.")]
  )
])
