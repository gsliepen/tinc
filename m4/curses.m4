dnl Check to find the curses headers/libraries

AC_DEFUN([tinc_CURSES],
[
  AC_ARG_ENABLE([curses],
    AS_HELP_STRING([--disable-curses], [disable curses support]))
  AS_IF([test "x$enable_curses" != "xno"], [
  AC_DEFINE(HAVE_CURSES, 1, [have curses support])
    curses=true
    AC_ARG_WITH(curses,
      AS_HELP_STRING([--with-curses=DIR], [curses base directory, or:]),
      [curses="$withval"
       CPPFLAGS="$CPPFLAGS -I$withval/include"
       LDFLAGS="$LDFLAGS -L$withval/lib"]
    )

    AC_ARG_WITH(curses-include,
      AS_HELP_STRING([--with-curses-include=DIR], [curses headers directory]),
      [curses_include="$withval"
       CPPFLAGS="$CPPFLAGS -I$withval"]
    )

    AC_ARG_WITH(curses-lib,
      AS_HELP_STRING([--with-curses-lib=DIR], [curses library directory]),
      [curses_lib="$withval"
       LDFLAGS="$LDFLAGS -L$withval"]
    )

    AC_CHECK_HEADERS(curses.h,
      [],
      [AC_MSG_ERROR("curses header files not found."); break]
    )

    AC_CHECK_LIB(curses, initscr,
      [CURSES_LIBS="-lcurses"],
      [AC_MSG_ERROR("curses libraries not found.")]
    )
  ])

  AC_SUBST(CURSES_LIBS)
])
