/*
    ipv6.h -- missing IPv6 related definitions
    Copyright (C) 2003 Ivo Timmermans <ivo@o2w.nl>
                  2003 Guus Sliepen <guus@sliepen.eu.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    $Id: ipv6.h,v 1.1.2.1 2003/07/07 11:13:31 guus Exp $
*/

#ifndef __TINC_IPV6_H__
#define __TINC_IPV6_H__

#include "config.h"

#include <netinet/in.h>
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

#ifndef HAVE_STRUCT_IN6_ADDR
struct in6_addr {
	union {
		uint8_t u6_addr8[16];
		uint16_t u6_addr16[8];
		uint32_t u6_addr32[4];
	} in6_u;
};
#define s6_addr in6_u.u6_addr8
#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32
#endif

#ifndef HAVE_STRUCT_SOCKADDR_IN6
struct sockaddr_in6 {
	in_port_t sin6_port;
	uint32_t sin6_flowinfo;
	struct in6_addr sin6_addr;
	uint32_t sin6_scope_id;
};
#endif

#ifndef HAVE_NETINET_IP6_H
struct ip6_hdr {
	union {
		struct ip6_hdrctl {
			uint32_t ip6_un1_flow;
			uint16_t ip6_un1_plen;
			uint8_t ip6_un1_nxt;
			uint8_t ip6_un1_hlim;
		} ip6_un1;
		uint8_t ip6_un2_vfc;
	} ip6_ctlun;
	struct in6_addr ip6_src;
	struct in6_addr ip6_dst;
};

struct icmp6_hdr {
	uint8_t icmp6_type;
	uint8_t icmp6_code;
	uint16_t icmp6_cksum;
	union {
		uint32_t icmp6_un_data32[1];
		uint16_t icmp6_un_data16[2];
		uint8_t icmp6_un_data8[4];
	} icmp6_dataun;
};
#define ICMP6_DST_UNREACH_NOROUTE 0
#define ICMP6_DST_UNREACH 1
#define ICMP6_DST_UNREACH_ADDR 3
#define ND_NEIGHBOR_SOLICIT 135
#define ND_NEIGHBOR_ADVERT 136

struct nd_neighbor_solicit {
	struct icmp6_hdr nd_ns_hdr;
	struct in6_addr nd_ns_target;
};
#define ND_OPT_SOURCE_LINKADDR 1
#define ND_OPT_TARGET_LINKADDR 2

struct nd_opt_hdr {
	uint8_t nd_opt_type;
	uint8_t nd_opt_len;
};
#endif

#endif /* __TINC_IPV6_H__ */
