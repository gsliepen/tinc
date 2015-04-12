/*
    ipv4.h -- missing IPv4 related definitions
    Copyright (C) 2005 Ivo Timmermans
                  2006-2012 Guus Sliepen <guus@tinc-vpn.org>

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

#ifndef __TINC_IPV4_H__
#define __TINC_IPV4_H__

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH 3
#endif

#ifndef ICMP_FRAG_NEEDED
#define ICMP_FRAG_NEEDED 4
#endif

#ifndef ICMP_NET_UNKNOWN
#define ICMP_NET_UNKNOWN 6
#endif

#ifndef ICMP_TIME_EXCEEDED
#define ICMP_TIME_EXCEEDED 11
#endif

#ifndef ICMP_EXC_TTL
#define ICMP_EXC_TTL 0
#endif

#ifndef ICMP_NET_UNREACH
#define ICMP_NET_UNREACH 0
#endif

#ifndef ICMP_NET_ANO
#define ICMP_NET_ANO 9
#endif

#ifndef IP_MSS
#define       IP_MSS          576
#endif

#ifndef HAVE_STRUCT_IP
struct ip {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ip_hl:4;
	unsigned int ip_v:4;
#else
	unsigned int ip_v:4;
	unsigned int ip_hl:4;
#endif
	uint8_t ip_tos;
	uint16_t ip_len;
	uint16_t ip_id;
	uint16_t ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
	uint8_t ip_ttl;
	uint8_t ip_p;
	uint16_t ip_sum;
	struct in_addr ip_src, ip_dst;
} __attribute__ ((__gcc_struct__, __packed__));
#endif

#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff
#endif

#ifndef HAVE_STRUCT_ICMP
struct icmp {
	uint8_t icmp_type;
	uint8_t icmp_code;
	uint16_t icmp_cksum;
	union {
		uint8_t ih_pptr;
		struct in_addr ih_gwaddr;
		struct ih_idseq {
			uint16_t icd_id;
			uint16_t icd_seq;
		} ih_idseq;
		uint32_t ih_void;


		struct ih_pmtu {
			uint16_t ipm_void;
			uint16_t ipm_nextmtu;
		} ih_pmtu;

		struct ih_rtradv {
			uint8_t irt_num_addrs;
			uint8_t irt_wpa;
			uint16_t irt_lifetime;
		} ih_rtradv;
	} icmp_hun;
#define icmp_pptr icmp_hun.ih_pptr
#define icmp_gwaddr icmp_hun.ih_gwaddr
#define icmp_id icmp_hun.ih_idseq.icd_id
#define icmp_seq icmp_hun.ih_idseq.icd_seq
#define icmp_void icmp_hun.ih_void
#define icmp_pmvoid icmp_hun.ih_pmtu.ipm_void
#define icmp_nextmtu icmp_hun.ih_pmtu.ipm_nextmtu
#define icmp_num_addrs icmp_hun.ih_rtradv.irt_num_addrs
#define icmp_wpa icmp_hun.ih_rtradv.irt_wpa
#define icmp_lifetime icmp_hun.ih_rtradv.irt_lifetime
	union {
		struct {
			uint32_t its_otime;
			uint32_t its_rtime;
			uint32_t its_ttime;
		} id_ts;
		struct {
			struct ip idi_ip;
		} id_ip;
		uint32_t id_mask;
		uint8_t id_data[1];
	} icmp_dun;
#define icmp_otime icmp_dun.id_ts.its_otime
#define icmp_rtime icmp_dun.id_ts.its_rtime
#define icmp_ttime icmp_dun.id_ts.its_ttime
#define icmp_ip icmp_dun.id_ip.idi_ip
#define icmp_radv icmp_dun.id_radv
#define icmp_mask icmp_dun.id_mask
#define icmp_data icmp_dun.id_data
} __attribute__ ((__gcc_struct__, __packed__));
#endif

#endif /* __TINC_IPV4_H__ */
