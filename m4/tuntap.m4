dnl Check to find out whether the running kernel has support for TUN/TAP

AC_DEFUN(tinc_TUNTAP,
[
AC_CACHE_CHECK([for linux/if_tun.h], tinc_cv_linux_if_tun_h,
[ AC_TRY_COMPILE([#include <linux/if_tun.h>],
  [int a = IFF_TAP],
  if_tun_h="linux/if_tun.h",
  if_tun_h="no")
   if test $if_tun_h = no; then
    AC_MSG_RESULT(none)
  else
    AC_DEFINE(HAVE_TUNTAP)
    AC_DEFINE_UNQUOTED(LINUX_IF_TUN_H, "$if_tun_h")
    AC_SUBST(LINUX_IF_TUN_H)
    AC_MSG_RESULT($if_tun_h)
  fi
  AC_SUBST(HAVE_TUNTAP)
])
])
