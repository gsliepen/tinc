/*
    ethernet.h -- missing Ethernet related definitions
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

#ifndef __TINC_ETHERNET_H__
#define __TINC_ETHERNET_H__

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER 1
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#ifndef HAVE_STRUCT_ETHER_HEADER
struct ether_header {
	uint8_t ether_dhost[ETH_ALEN];
	uint8_t ether_shost[ETH_ALEN];
	uint16_t ether_type;
} __attribute__ ((__packed__));
#endif

#ifndef HAVE_STRUCT_ARPHDR
struct arphdr {
	uint16_t ar_hrd;
	uint16_t ar_pro;
	uint8_t ar_hln;
	uint8_t ar_pln;
	uint16_t ar_op;
} __attribute__ ((__packed__));

#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#define ARPOP_RREQUEST 3
#define ARPOP_RREPLY 4
#define ARPOP_InREQUEST 8
#define ARPOP_InREPLY 9
#define ARPOP_NAK 10
#endif

#ifndef HAVE_STRUCT_ETHER_ARP
struct  ether_arp {
	struct  arphdr ea_hdr;
	uint8_t arp_sha[ETH_ALEN];
	uint8_t arp_spa[4];
	uint8_t arp_tha[ETH_ALEN];
	uint8_t arp_tpa[4];
} __attribute__ ((__packed__));
#define arp_hrd ea_hdr.ar_hrd
#define arp_pro ea_hdr.ar_pro
#define arp_hln ea_hdr.ar_hln
#define arp_pln ea_hdr.ar_pln
#define arp_op ea_hdr.ar_op
#endif

#endif /* __TINC_ETHERNET_H__ */
