dnl Check to find the libevent headers/libraries

AC_DEFUN([tinc_LIBEVENT],
[
  AC_ARG_WITH(libevent,
    AS_HELP_STRING([--with-libevent=DIR], [libevent base directory, or:]),
    [libevent="$withval"
     CPPFLAGS="$CPPFLAGS -I$withval/include"
     LDFLAGS="$LDFLAGS -L$withval/lib"]
  )

  AC_ARG_WITH(libevent-include,
    AS_HELP_STRING([--with-libevent-include=DIR], [libevent headers directory]),
    [libevent_include="$withval"
     CPPFLAGS="$CPPFLAGS -I$withval"]
  )

  AC_ARG_WITH(libevent-lib,
    AS_HELP_STRING([--with-libevent-lib=DIR], [libevent library directory]),
    [libevent_lib="$withval"
     LDFLAGS="$LDFLAGS -L$withval"]
  )

  AC_CHECK_HEADERS(event.h,
    [],
    [AC_MSG_ERROR("libevent header files not found."); break]
  )

  AC_CHECK_LIB(event, event_init,
    [LIBS="-levent $LIBS"],
    [AC_MSG_ERROR("libevent libraries not found.")]
  )
])
