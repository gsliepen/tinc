dnl Check to find out whether the running kernel has support for TUN/TAP

AC_DEFUN(tinc_TUNTAP,
[
AC_ARG_WITH(kernel,
  [  --with-kernel=dir       give the directory with kernel sources]
  [                        (default: /usr/src/linux)],
  kerneldir="$withval",
  kerneldir="/usr/src/linux"
)

AC_CACHE_CHECK([for linux/if_tun.h], tinc_cv_linux_if_tun_h,
[ 
  AC_TRY_COMPILE([#include "$kerneldir/include/linux/if_tun.h"],
    [int a = IFF_TAP;],
    if_tun_h="\"$kerneldir/include/linux/if_tun.h\"",
    [AC_TRY_COMPILE([#include <linux/if_tun.h>],
      [int a = IFF_TAP;],
      if_tun_h="default",
      if_tun_h="no"
    )]
  )

  if test $if_tun_h = no; then
    tinc_cv_linux_if_tun_h=none
  else
    tinc_cv_linux_if_tun_h="$if_tun_h"
  fi
])

if test $tinc_cv_linux_if_tun_h != none; then
  AC_DEFINE(HAVE_TUNTAP)
  if test $tinc_cv_linux_if_tun_h != default; then
   AC_DEFINE_UNQUOTED(LINUX_IF_TUN_H, $tinc_cv_linux_if_tun_h)
  fi
fi
AC_SUBST(LINUX_IF_TUN_H)
AC_SUBST(HAVE_TUNTAP)
])
