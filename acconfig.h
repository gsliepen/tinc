/* Define to the name name of this package */
#undef PACKAGE

/* Define to the version of the package */
#undef VERSION

/* Define to rpl_malloc if the replacement function should be used.  */
#undef malloc

/* Define to rpl_realloc if the replacement function should be used.  */
#undef realloc

/* This is always defined.  It enables GNU extensions on systems that
   have them.  */
#if !defined(_GNU_SOURCE)
# undef _GNU_SOURCE
#endif

#if !defined(__USE_BSD)
# undef __USE_BSD
#endif


/* Define to 1 if NLS is requested.  */
#undef ENABLE_NLS

/* Define as 1 if you have catgets and don't want to use GNU gettext.  */
#undef HAVE_CATGETS

/* Define as 1 if you have gettext and don't want to use GNU gettext.  */
#undef HAVE_GETTEXT

/* Define if your locale.h file contains LC_MESSAGES.  */
#undef HAVE_LC_MESSAGES

/* Define to 1 if you have the stpcpy function.  */
#undef HAVE_STPCPY

/* For getopt */
#if HAVE_STDLIB_H
# define getopt system_getopt
# include <stdlib.h>
# undef getopt
#endif

/* Linux */
#undef HAVE_LINUX

/* FreeBSD */
#undef HAVE_FREEBSD

/* OpenBSD */
#undef HAVE_OPENBSD

/* Solaris */
#undef HAVE_SOLARIS

/* NetBSD */
#undef HAVE_NETBSD

/* Define to the location of the kernel sources */
#undef CONFIG_TINC_KERNELDIR

/* Define to 1 if tun/tap support is enabled and found */
#undef HAVE_TUNTAP

/* Define to the location of if_tun.h */
#undef LINUX_IF_TUN_H

/* Define to 1 if support for jumbograms is enabled */
#undef ENABLE_JUMBOGRAMS

/* Define to 1 if checkpoint tracing is enabled */
#undef ENABLE_TRACING

/* Define to enable use of old SSLeay_add_all_algorithms() function */
#undef HAVE_SSLEAY_ADD_ALL_ALGORITHMS
