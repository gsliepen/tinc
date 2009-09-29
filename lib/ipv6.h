/*
    ipv6.h -- missing IPv6 related definitions
    Copyright (C) 2005 Ivo Timmermans
                  2006 Guus Sliepen <guus@tinc-vpn.org>

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

#ifndef __TINC_IPV6_H__
#define __TINC_IPV6_H__

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
} __attribute__ ((__packed__));
#define s6_addr in6_u.u6_addr8
#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32
#endif

#ifndef HAVE_STRUCT_SOCKADDR_IN6
struct sockaddr_in6 {
	uint16_t sin6_family;
	uint16_t sin6_port;
	uint32_t sin6_flowinfo;
	struct in6_addr sin6_addr;
	uint32_t sin6_scope_id;
} __attribute__ ((__packed__));
#endif

#ifndef IN6_IS_ADDR_V4MAPPED
#define IN6_IS_ADDR_V4MAPPED(a) \
        ((((__const uint32_t *) (a))[0] == 0) \
        && (((__const uint32_t *) (a))[1] == 0) \
        && (((__const uint32_t *) (a))[2] == htonl (0xffff)))
#endif

#ifndef HAVE_STRUCT_IP6_HDR
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
} __attribute__ ((__packed__));
#define ip6_vfc ip6_ctlun.ip6_un2_vfc
#define ip6_flow ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops ip6_ctlun.ip6_un1.ip6_un1_hlim
#endif

#ifndef HAVE_STRUCT_ICMP6_HDR
struct icmp6_hdr {
	uint8_t icmp6_type;
	uint8_t icmp6_code;
	uint16_t icmp6_cksum;
	union {
		uint32_t icmp6_un_data32[1];
		uint16_t icmp6_un_data16[2];
		uint8_t icmp6_un_data8[4];
	} icmp6_dataun;
} __attribute__ ((__packed__));
#define ICMP6_DST_UNREACH_NOROUTE 0
#define ICMP6_DST_UNREACH 1
#define ICMP6_PACKET_TOO_BIG 2
#define ICMP6_DST_UNREACH_ADDR 3
#define ND_NEIGHBOR_SOLICIT 135
#define ND_NEIGHBOR_ADVERT 136
#define icmp6_data32 icmp6_dataun.icmp6_un_data32
#define icmp6_data16 icmp6_dataun.icmp6_un_data16
#define icmp6_data8 icmp6_dataun.icmp6_un_data8
#define icmp6_mtu icmp6_data32[0]
#endif

#ifndef HAVE_STRUCT_ND_NEIGHBOR_SOLICIT
struct nd_neighbor_solicit {
	struct icmp6_hdr nd_ns_hdr;
	struct in6_addr nd_ns_target;
} __attribute__ ((__packed__));
#define ND_OPT_SOURCE_LINKADDR 1
#define ND_OPT_TARGET_LINKADDR 2
#define nd_ns_type nd_ns_hdr.icmp6_type
#define nd_ns_code nd_ns_hdr.icmp6_code
#define nd_ns_cksum nd_ns_hdr.icmp6_cksum
#define nd_ns_reserved nd_ns_hdr.icmp6_data32[0]
#endif

#ifndef HAVE_STRUCT_ND_OPT_HDR
struct nd_opt_hdr {
	uint8_t nd_opt_type;
	uint8_t nd_opt_len;
} __attribute__ ((__packed__));
#endif

#endif /* __TINC_IPV6_H__ */
