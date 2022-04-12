#ifndef TINC_HAVE_H
#define TINC_HAVE_H

/*
    have.h -- include headers which are known to exist
    Copyright (C) 1998-2005 Ivo Timmermans
                  2003-2021 Guus Sliepen <guus@tinc-vpn.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifdef HAVE_WINDOWS
#define WINVER 0x0600
#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_WARNINGS
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <limits.h>
#include <math.h>
#include <time.h>

#ifdef HAVE_STATIC_ASSERT
#define STATIC_ASSERT(expr, msg) _Static_assert((expr), msg)
#else
#define STATIC_ASSERT(check, msg)
#endif

#ifdef HAVE_ATTR_PACKED
#define PACKED(...) __VA_ARGS__ __attribute__((__packed__))
#else
#ifdef _MSC_VER
#define PACKED(...) __pragma(pack(push, 1)) __VA_ARGS__ __pragma(pack(pop))
#else
#warning Your compiler does not support __packed__. Use at your own risk.
#endif
#endif

#ifdef HAVE_ATTR_MALLOC
#define ATTR_MALLOC __attribute__((__malloc__))
#else
#define ATTR_MALLOC
#endif

#ifdef HAVE_ATTR_NONNULL
#define ATTR_NONNULL __attribute__((__nonnull__))
#else
#define ATTR_NONNULL
#endif

#ifdef HAVE_ATTR_WARN_UNUSED_RESULT
#define ATTR_WARN_UNUSED __attribute__((__warn_unused_result__))
#else
#define ATTR_WARN_UNUSED
#endif

#ifdef HAVE_ATTR_FORMAT
#define ATTR_FORMAT(func, str, nonstr) __attribute__((format(func, str, nonstr)))
#else
#define ATTR_FORMAT(func, str, nonstr)
#endif

#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#elif defined(HAVE_NETBSD)
#define alloca(size) __builtin_alloca(size)
#endif

#ifdef HAVE_WINDOWS
#ifdef HAVE_W32API_H
#include <w32api.h>
#endif

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#ifdef _MSC_VER
#include <io.h>
#include <process.h>
#include <direct.h>
#endif
#endif // HAVE_WINDOWS

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

/* Include system specific headers */

#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_SYS_RANDOM_H
#include <sys/random.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#elif defined(_MSC_VER)
#include "dirent.h"
#endif

/* SunOS really wants sys/socket.h BEFORE net/if.h,
   and FreeBSD wants these lines below the rest. */

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_NET_IF_TYPES_H
#include <net/if_types.h>
#endif

#ifdef HAVE_NET_IF_TUN_H
#include <net/if_tun.h>
#endif

#ifdef HAVE_NET_TUN_IF_TUN_H
#include <net/tun/if_tun.h>
#endif

#ifdef HAVE_NET_IF_TAP_H
#include <net/if_tap.h>
#endif

#ifdef HAVE_NET_TAP_IF_TAP_H
#include <net/tap/if_tap.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif

#ifdef HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#ifdef HAVE_NET_IF_ARP_H
#include <net/if_arp.h>
#endif

#ifdef HAVE_NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#endif

#ifdef HAVE_NETINET_ICMP6_H
#include <netinet/icmp6.h>
#endif

#ifdef HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif

#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif

#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif

#ifdef HAVE_LINUX_IF_TUN_H
#include <linux/if_tun.h>
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#else
#include "getopt.h"
#endif

#ifdef STATUS
#undef STATUS
#endif

#ifdef HAVE_WINDOWS
#define SLASH "\\"
#else
#define SLASH "/"
#endif

#endif
