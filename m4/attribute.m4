dnl Check to find out whether function attributes are supported.
dnl If they are not, #define them to be nothing.

AC_DEFUN([tinc_ATTRIBUTE],
[
  AC_CACHE_CHECK([for working $1 attribute], tinc_cv_attribute_$1,
  [ 
    tempcflags="$CFLAGS"
    CFLAGS="$CFLAGS -Wall -Werror"
    AC_COMPILE_IFELSE(
      [AC_LANG_SOURCE(
        [void test(void) __attribute__ (($1));
	 void test(void) { return; }
	],
       )],
       [tinc_cv_attribute_$1=yes],
       [tinc_cv_attribute_$1=no]
     )
     CFLAGS="$tempcflags"
   ])

   if test ${tinc_cv_attribute_$1} = no; then
     AC_DEFINE([$1], [], [Defined if the $1 attribute is not supported.])
   fi
])
