dnl Check to find the readline headers/libraries

AC_DEFUN([tinc_READLINE],
[
  AC_ARG_ENABLE([readline],
    AS_HELP_STRING([--disable-readline], [disable readline support]))
  AS_IF([test "x$enable_readline" != "xno"], [
  AC_DEFINE(HAVE_READLINE, 1, [have readline support])
    readline=true
    AC_ARG_WITH(readline,
      AS_HELP_STRING([--with-readline=DIR], [readline base directory, or:]),
      [readline="$withval"
       CPPFLAGS="$CPPFLAGS -I$withval/include"
       LDFLAGS="$LDFLAGS -L$withval/lib"]
    )

    AC_ARG_WITH(readline-include,
      AS_HELP_STRING([--with-readline-include=DIR], [readline headers directory]),
      [readline_include="$withval"
       CPPFLAGS="$CPPFLAGS -I$withval"]
    )

    AC_ARG_WITH(readline-lib,
      AS_HELP_STRING([--with-readline-lib=DIR], [readline library directory]),
      [readline_lib="$withval"
       LDFLAGS="$LDFLAGS -L$withval"]
    )

    AC_CHECK_HEADERS([readline/readline.h readline/history.h],
      [],
      [AC_MSG_ERROR("readline header files not found."); break]
    )

    AC_CHECK_LIB(readline, readline,
      [READLINE_LIBS="-lreadline"],
      [AC_MSG_ERROR("readline library not found.")],
      [$CURSES_LIBS]
    )
  ])

  AC_SUBST(READLINE_LIBS)
])
