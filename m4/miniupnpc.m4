dnl Check to find the miniupnpc headers/libraries

AC_DEFUN([tinc_MINIUPNPC],
[
  AC_ARG_ENABLE([miniupnpc],
    AS_HELP_STRING([--enable-miniupnpc], [enable miniupnpc support]))
  AS_IF([test "x$enable_miniupnpc" = "xyes"], [
  AC_DEFINE(HAVE_MINIUPNPC, 1, [have miniupnpc support])
    AC_ARG_WITH(miniupnpc,
      AS_HELP_STRING([--with-miniupnpc=DIR], [miniupnpc base directory, or:]),
      [miniupnpc="$withval"
       CPPFLAGS="$CPPFLAGS -I$withval/include"
       LDFLAGS="$LDFLAGS -L$withval/lib"]
    )

    AC_ARG_WITH(miniupnpc-include,
      AS_HELP_STRING([--with-miniupnpc-include=DIR], [miniupnpc headers directory]),
      [miniupnpc_include="$withval"
       CPPFLAGS="$CPPFLAGS -I$withval"]
    )

    AC_ARG_WITH(miniupnpc-lib,
      AS_HELP_STRING([--with-miniupnpc-lib=DIR], [miniupnpc library directory]),
      [miniupnpc_lib="$withval"
       LDFLAGS="$LDFLAGS -L$withval"]
    )

    AC_CHECK_HEADERS(miniupnpc/miniupnpc.h,
      [],
      [AC_MSG_ERROR("miniupnpc header files not found."); break]
    )

    AC_CHECK_LIB(miniupnpc, upnpDiscover,
      [MINIUPNPC_LIBS="$LIBS -lminiupnpc"],
      [AC_MSG_ERROR("miniupnpc libraries not found.")]
    )
  ])

  AC_SUBST(MINIUPNPC_LIBS)
])
