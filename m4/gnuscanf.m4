dnl Check for a scanf that understands about %as as format specifier

AC_DEFUN(tinc_SCANF_AS,
[
  AC_CACHE_CHECK([for a scanf that groks %as], tinc_cv_scanf_as,
  [
    AC_TRY_RUN([
/* Very naive program which will probably give a segmentation
   fault if the sscanf doesn't work as expected. */
#include <stdio.h>
int main() {
  char*s = NULL;
  sscanf("string\n", "%as\n", &s);
  if(s == NULL)
    return 1;
  return strcmp("string", s);
}
    ], [tinc_cv_scanf_as="yes"], [tinc_cv_scanf_as="no"])
  ])

if test "$tinc_cv_scanf_as" = "yes" ; then
  AC_DEFINE(HAVE_SCANF_AS)
  AC_SUBST(HAVE_SCANF_AS)
fi
])
