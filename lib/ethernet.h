/*
    ethernet.h -- missing Ethernet related definitions
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

    $Id: ethernet.h,v 1.1.2.1 2003/07/18 12:16:23 guus Exp $
*/

#ifndef __TINC_ETHERNET_H__
#define __TINC_ETHERNET_H__

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER 1
#endif

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif

#ifndef HAVE_NET_IF_ARP_H

struct arphdr {
	unsigned short int ar_hrd;
	unsigned short int ar_pro;
	unsigned char ar_hln;
	unsigned char ar_pln; 
	unsigned short int ar_op; 
};

#define ARPOP_REQUEST 1 
#define ARPOP_REPLY 2 
#define ARPOP_RREQUEST 3 
#define ARPOP_RREPLY 4 
#define ARPOP_InREQUEST 8 
#define ARPOP_InREPLY 9 
#define ARPOP_NAK 10 

#endif

#ifndef HAVE_NETINET_IF_ETHER_H

struct  ether_arp {
	struct  arphdr ea_hdr;
	uint8_t arp_sha[ETH_ALEN];
	uint8_t arp_spa[4];
	uint8_t arp_tha[ETH_ALEN];
	uint8_t arp_tpa[4];
};
#define arp_hrd ea_hdr.ar_hrd
#define arp_pro ea_hdr.ar_pro
#define arp_hln ea_hdr.ar_hln
#define arp_pln ea_hdr.ar_pln
#define arp_op ea_hdr.ar_op

#endif

#endif /* __TINC_ETHERNET_H__ */
