dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([tinc], m4_esyscmd_s((git describe || echo UNKNOWN) | sed 's/release-//'))
AC_CONFIG_SRCDIR([src/tincd.c])
AC_GNU_SOURCE
AM_INIT_AUTOMAKE([std-options subdir-objects nostdinc silent-rules -Wall])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
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
AC_PROG_LN_S

AM_PROG_CC_C_O

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
    LIBS="$LIBS -lws2_32 -lgdi32 -lcrypt32 -liphlpapi"
    LDFLAGS="$LDFLAGS -static"
    CPPFLAGS="$CPPFLAGS -DMINIUPNP_STATICLIB"
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

AC_ARG_WITH(systemd,
  AS_HELP_STRING([--with-systemd@<:@=DIR@:>@], [install systemd service files @<:@to DIR if specified@:>@]),
  [ systemd=true; systemd_path="$with_systemd" ],
  [ systemd=false ]
)

AS_IF([test "x$with_systemd" = "xyes"], [systemd_path="/lib/systemd/system"],
      [AS_IF([test "x$with_systemd" = "xno"], [systemd=false])])

AC_SUBST(systemd_path, $systemd_path)

AM_CONDITIONAL(LINUX, test "$linux" = true)
AM_CONDITIONAL(BSD, test "$bsd" = true)
AM_CONDITIONAL(SOLARIS, test "$solaris" = true)
AM_CONDITIONAL(MINGW, test "$mingw" = true)
AM_CONDITIONAL(CYGWIN, test "$cygwin" = true)
AM_CONDITIONAL(UML, test "$uml" = true)
AM_CONDITIONAL(VDE, test "$vde" = true)
AM_CONDITIONAL(TUNEMU, test "$tunemu" = true)
AM_CONDITIONAL(WITH_SYSTEMD, test "$systemd" = true)

AC_CACHE_SAVE

AS_IF([test -d /sw/include], [CPPFLAGS="$CPPFLAGS -I/sw/include"])
AS_IF([test -d /sw/lib], [LIBS="$LIBS -L/sw/lib"])

dnl Compiler hardening flags
dnl No -fstack-protector-all because it doesn't work on all platforms or architectures.

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

dnl Checks for header files.
dnl We do this in multiple stages, because unlike Linux all the other operating systems really suck and don't include their own dependencies.

AC_CHECK_HEADERS([syslog.h sys/file.h sys/ioctl.h sys/mman.h sys/param.h sys/resource.h sys/socket.h sys/time.h sys/un.h sys/wait.h netdb.h arpa/inet.h dirent.h getopt.h])
AC_CHECK_HEADERS([net/if.h net/if_types.h net/ethernet.h net/if_arp.h netinet/in_systm.h netinet/in.h netinet/in6.h netpacket/packet.h],
  [], [], [#include "$srcdir/src/have.h"]
)
AC_CHECK_HEADERS([netinet/if_ether.h netinet/ip.h netinet/ip6.h resolv.h],
  [], [], [#include "$srcdir/src/have.h"]
)
AC_CHECK_HEADERS([netinet/tcp.h netinet/ip_icmp.h netinet/icmp6.h],
  [], [], [#include "$srcdir/src/have.h"]
)

dnl Checks for typedefs, structures, and compiler characteristics.
tinc_ATTRIBUTE(__malloc__)
tinc_ATTRIBUTE(__warn_unused_result__)

AC_CHECK_TYPES([struct ether_header, struct arphdr, struct ether_arp, struct ip, struct icmp, struct ip6_hdr, struct icmp6_hdr, struct nd_neighbor_solicit, struct nd_opt_hdr], , ,
  [#include "$srcdir/src/have.h"]
)

dnl Checks for library functions.
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([asprintf daemon fchmod flock ftime fork gettimeofday mlockall putenv recvmmsg strsignal nanosleep unsetenv vsyslog devname fdevname],
  [], [], [#include "$srcdir/src/have.h"]
)

AC_CHECK_FUNC(getopt_long, [getopt=true; AC_DEFINE(HAVE_GETOPT_LONG, 1, [getopt_long()])], [getopt=false])
AM_CONDITIONAL(GETOPT, test "$getopt" = true)

AC_CHECK_DECLS([res_init], [AC_CHECK_LIB(resolv, res_init)], [], [
  #include <netinet/in.h>
  #include <resolv.h>
])

dnl Operating system specific checks
case $host_os in
  *linux*)
    AC_CHECK_HEADERS([linux/if_tun.h],
      [], [AC_MSG_ERROR([Required header file missng])], [#include "$srcdir/src/have.h"]
    )
  ;;
  *bsd*|*dragonfly*|*darwin*)
    AC_CHECK_HEADERS([net/if_tun.h net/if_utun.h net/tun/if_tun.h net/if_tap.h net/tap/if_tap.h],
      [], [], [#include "$srcdir/src/have.h"]
    )
  ;;
  *solaris*)
    AC_CHECK_FUNC(socket, [], [AC_CHECK_LIB(socket, connect)])
  ;;
  *)
  ;;
esac

AC_CACHE_SAVE

AC_ARG_ENABLE(legacy-protocol,
  AS_HELP_STRING([--disable-legacy-protocol], [disable support for the legacy (tinc 1.0) protocol]),
  [ AS_IF([test "x$enable_legacy_protocol" = "xno"],
    [ AC_DEFINE(DISABLE_LEGACY, 1, [Disable support for the legacy (tinc 1.0) protocol]) ])
  ]
)

dnl These are defined in files in m4/

dnl AC_ARG_WITH(libgcrypt, AC_HELP_STRING([--with-libgcrypt], [enable use of libgcrypt instead of OpenSSL])], [])
dnl AC_ARG_WITH(openssl, AC_HELP_STRING([--without-openssl], [disable support for OpenSSL])], [])

tinc_CURSES
tinc_READLINE
tinc_ZLIB
tinc_LZO

AS_IF([test "x$enable_legacy_protocol" != "xno"],
      [AS_IF([test -n "$with_libgcrypt"],
	     [gcrypt=true; tinc_LIBGCRYPT],
	     [openssl=true; tinc_OPENSSL])
      ]
)

AM_CONDITIONAL(OPENSSL, test -n "$openssl")
AM_CONDITIONAL(GCRYPT, test -n "$gcrypt")

tinc_MINIUPNPC
AM_CONDITIONAL(MINIUPNPC, test "x$enable_miniupnpc" = "xyes")

dnl Check if support for jumbograms is requested
AC_ARG_ENABLE(jumbograms,
  AS_HELP_STRING([--enable-jumbograms], [enable support for jumbograms (packets up to 9000 bytes)]),
  [ AS_IF([test "x$enable_jumbograms" = "xyes"],
      [ AC_DEFINE(ENABLE_JUMBOGRAMS, 1, [Support for jumbograms (packets up to 9000 bytes)]) ])
  ]
)

AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile gui/Makefile test/Makefile systemd/Makefile])

AC_OUTPUT
