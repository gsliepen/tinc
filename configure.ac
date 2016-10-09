dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([tinc], [1.0.29])
AC_CONFIG_SRCDIR([src/tincd.c])
AM_INIT_AUTOMAKE([1.11 check-news std-options subdir-objects nostdinc silent-rules -Wall])
AC_CONFIG_HEADERS([config.h])
AM_MAINTAINER_MODE
AM_SILENT_RULES([yes])

# Enable GNU extensions.
# Define this here, not in acconfig's @TOP@ section, since definitions
# in the latter don't make it into the configure-time tests.
AC_GNU_SOURCE
AC_DEFINE([__USE_BSD], 1, [Enable BSD extensions])

dnl Checks for programs.
AC_PROG_CC_C99
AC_PROG_CPP
AC_PROG_INSTALL

AM_PROG_CC_C_O

PKG_PROG_PKG_CONFIG

dnl Check and set OS

AC_CANONICAL_HOST

case $host_os in
  *linux*)
    linux=true
    AC_DEFINE(HAVE_LINUX, 1, [Linux])
  ;;
  *freebsd*)
    bsd=true
    AC_DEFINE(HAVE_FREEBSD, 1, [FreeBSD])
  ;;
  *darwin*)
    bsd=true
    AC_DEFINE(HAVE_DARWIN, 1, [Darwin (MacOS/X)])
  ;;
  *solaris*)
    solaris=true
    AC_DEFINE(HAVE_SOLARIS, 1, [Solaris/SunOS])
  ;;
  *openbsd*)
    bsd=true
    AC_DEFINE(HAVE_OPENBSD, 1, [OpenBSD])
  ;;
  *netbsd*)
    bsd=true
    AC_DEFINE(HAVE_NETBSD, 1, [NetBSD])
  ;;
  *dragonfly*)
    bsd=true
    AC_DEFINE(HAVE_DRAGONFLY, 1, [DragonFly])
  ;;
  *bsd*)
    bsd=true
    AC_MSG_WARN("Unknown BSD variant, tinc might not compile or work!")
    AC_DEFINE(HAVE_BSD, 1, [Unknown BSD variant])
  ;;
  *cygwin*)
    cygwin=true
    AC_DEFINE(HAVE_CYGWIN, 1, [Cygwin])
  ;;
  *mingw*)
    mingw=true
    AC_DEFINE(HAVE_MINGW, 1, [MinGW])
    LIBS="$LIBS -lws2_32 -lgdi32 -lcrypt32"
  ;;
  *)
    AC_MSG_ERROR("Unknown operating system.")
  ;;
esac

AC_ARG_ENABLE(uml,
  AS_HELP_STRING([--enable-uml], [enable support for User Mode Linux]),
  [ AS_IF([test "x$enable_uml" = "xyes"],
      [ AC_DEFINE(ENABLE_UML, 1, [Support for UML])
        uml=true
      ],
      [uml=false])
  ],
  [uml=false]
)

AC_ARG_ENABLE(vde,
  AS_HELP_STRING([--enable-vde], [enable support for Virtual Distributed Ethernet]),
  [ AS_IF([test "x$enable_vde" = "xyes"],
      [ AC_CHECK_HEADERS(libvdeplug_dyn.h, [], [AC_MSG_ERROR([VDE plug header files not found.]); break])
        AC_DEFINE(ENABLE_VDE, 1, [Support for VDE])
        vde=true
      ],
      [vde=false])
  ],
  [vde=false]
)

AC_ARG_ENABLE(tunemu,
  AS_HELP_STRING([--enable-tunemu], [enable support for the tunemu driver]),
  [ AS_IF([test "x$enable_tunemu" = "xyes"],
      [ AC_DEFINE(ENABLE_TUNEMU, 1, [Support for tunemu])
        tunemu=true
      ],
      [tunemu=false])
  ],
  [tunemu=false]
)

AC_ARG_WITH(windows2000,
  AS_HELP_STRING([--with-windows2000], [compile with support for Windows 2000. This disables support for tunneling over existing IPv6 networks.]),
  [ AS_IF([test "x$with_windows2000" = "xyes"],
      [AC_DEFINE(WITH_WINDOWS2000, 1, [Compile with support for Windows 2000])])
  ]
)

AC_ARG_WITH([systemdsystemunitdir],
     [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files])],,
     [with_systemdsystemunitdir=auto])
AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"], [
     def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)

     AS_IF([test "x$def_systemdsystemunitdir" = "x"],
   [AS_IF([test "x$with_systemdsystemunitdir" = "xyes"],
    [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
    with_systemdsystemunitdir=no],
   [with_systemdsystemunitdir="$def_systemdsystemunitdir"])])
AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
      [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])

AM_CONDITIONAL(LINUX, test "$linux" = true)
AM_CONDITIONAL(BSD, test "$bsd" = true)
AM_CONDITIONAL(SOLARIS, test "$solaris" = true)
AM_CONDITIONAL(MINGW, test "$mingw" = true)
AM_CONDITIONAL(CYGWIN, test "$cygwin" = true)
AM_CONDITIONAL(UML, test "$uml" = true)
AM_CONDITIONAL(VDE, test "$vde" = true)
AM_CONDITIONAL(TUNEMU, test "$tunemu" = true)

AC_CACHE_SAVE

if test -d /sw/include ; then
  CPPFLAGS="$CPPFLAGS -I/sw/include"
fi
if test -d /sw/lib ; then
  LIBS="$LIBS -L/sw/lib"
fi

dnl Compiler hardening flags
dnl No -fstack-protector-all because it doesn't work on all platforms or architectures.

AX_CFLAGS_WARN_ALL(CFLAGS)

AC_ARG_ENABLE([hardening], AS_HELP_STRING([--disable-hardening], [disable compiler and linker hardening flags]))
AS_IF([test "x$enable_hardening" != "xno"],
  [AX_CHECK_COMPILE_FLAG([-DFORTIFY_SOURCE=2], [CPPFLAGS="$CPPFLAGS -DFORTIFY_SOURCE=2"])
   AX_CHECK_COMPILE_FLAG([-fwrapv], [CPPFLAGS="$CPPFLAGS -fwrapv"],
   AX_CHECK_COMPILE_FLAG([-fno-strict-overflow], [CPPFLAGS="$CPPFLAGS -fno-strict-overflow"]))
   case $host_os in
     *mingw*)
       AX_CHECK_LINK_FLAG([-Wl,--dynamicbase], [LDFLAGS="$LDFLAGS -Wl,--dynamicbase"])
       AX_CHECK_LINK_FLAG([-Wl,--nxcompat], [LDFLAGS="$LDFLAGS -Wl,--nxcompat"])
       ;;
     *)
       AX_CHECK_COMPILE_FLAG([-fPIE], [CPPFLAGS="$CPPFLAGS -fPIE"])
       AX_CHECK_LINK_FLAG([-pie], [LDFLAGS="$LDFLAGS -pie"])
       ;;
   esac
   AX_CHECK_LINK_FLAG([-Wl,-z,relro], [LDFLAGS="$LDFLAGS -Wl,-z,relro"])
   AX_CHECK_LINK_FLAG([-Wl,-z,now], [LDFLAGS="$LDFLAGS -Wl,-z,now"])
  ]
);

dnl Checks for libraries.

dnl Checks for header files.
dnl We do this in multiple stages, because unlike Linux all the other operating systems really suck and don't include their own dependencies.

AC_HEADER_STDC
AC_CHECK_HEADERS([stdbool.h syslog.h sys/file.h sys/ioctl.h sys/mman.h sys/param.h sys/resource.h sys/socket.h sys/time.h time.h sys/uio.h sys/wait.h netdb.h arpa/inet.h arpa/nameser.h dirent.h getopt.h])
AC_CHECK_HEADERS([net/if.h net/if_types.h linux/if_tun.h net/if_tun.h net/if_utun.h net/tun/if_tun.h net/if_tap.h net/tap/if_tap.h net/ethernet.h net/if_arp.h netinet/in_systm.h netinet/in.h netinet/in6.h netpacket/packet.h],
  [], [], [#include "src/have.h"]
)
AC_CHECK_HEADERS([netinet/if_ether.h netinet/ip.h netinet/ip6.h resolv.h],
  [], [], [#include "src/have.h"]
)
AC_CHECK_HEADERS([netinet/tcp.h netinet/ip_icmp.h netinet/icmp6.h],
  [], [], [#include "src/have.h"]
)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_VOLATILE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

tinc_ATTRIBUTE(__malloc__)

AC_CHECK_TYPES([socklen_t, struct ether_header, struct arphdr, struct ether_arp, struct in_addr, struct addrinfo, struct ip, struct icmp, struct in6_addr, struct sockaddr_in6, struct ip6_hdr, struct icmp6_hdr, struct nd_neighbor_solicit, struct nd_opt_hdr], , ,
  [#include "src/have.h"]
)

dnl Checks for library functions.
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([asprintf daemon fchmod flock ftime fork get_current_dir_name gettimeofday mlockall pselect putenv random select strdup strerror strsignal strtol system unsetenv usleep vsyslog writev devname fdevname],
  [], [], [#include "src/have.h"]
)

AC_CHECK_FUNC(getopt_long, [getopt=true; AC_DEFINE(HAVE_GETOPT_LONG, 1, [getopt_long()])], [getopt=false])
AM_CONDITIONAL(GETOPT, test "$getopt" = true)

dnl Support for SunOS

AC_CHECK_FUNC(socket, [], [
  AC_CHECK_LIB(socket, connect)
])
AC_CHECK_FUNC(gethostbyname, [], [
  AC_CHECK_LIB(nsl, gethostbyname)
])

AC_CHECK_DECLS([freeaddrinfo, gai_strerror, getaddrinfo, getnameinfo],
  [], [], [#include "src/have.h"]
)

AC_CHECK_DECLS([res_init], [AC_CHECK_LIB(resolv, res_init)], [], [
  #include <netinet/in.h>
  #include <resolv.h>
])

AC_CACHE_SAVE

dnl These are defined in files in m4/

tinc_ZLIB
tinc_LZO
tinc_OPENSSL

dnl Check if support for jumbograms is requested
AC_ARG_ENABLE(jumbograms,
  AS_HELP_STRING([--enable-jumbograms], [enable support for jumbograms (packets up to 9000 bytes)]),
  [ AS_IF([test "x$enable_jumbograms" = "xyes"],
      [ AC_DEFINE(ENABLE_JUMBOGRAMS, 1, [Support for jumbograms (packets up to 9000 bytes)]) ])
  ]
)

AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile m4/Makefile distro/Makefile])

AC_OUTPUT
