/*
    route.c -- routing
    Copyright (C) 2000-2003 Ivo Timmermans <ivo@o2w.nl>,
                  2000-2003 Guus Sliepen <guus@sliepen.eu.org>

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

    $Id: route.c,v 1.1.2.73 2003/12/20 21:25:17 guus Exp $
*/

#include "system.h"

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

#include "avl_tree.h"
#include "connection.h"
#include "ethernet.h"
#include "ipv4.h"
#include "ipv6.h"
#include "logger.h"
#include "net.h"
#include "protocol.h"
#include "route.h"
#include "subnet.h"
#include "utils.h"

rmode_t routing_mode = RMODE_ROUTER;
bool priorityinheritance = false;
int macexpire = 600;
bool overwrite_mac = false;
mac_t mymac = {{0xFE, 0xFD, 0, 0, 0, 0}};

/* Sizes of various headers */

static const size_t ether_size = sizeof(struct ether_header);
static const size_t arp_size = sizeof(struct ether_arp);
static const size_t ip_size = sizeof(struct ip);
static const size_t icmp_size = sizeof(struct icmp) - sizeof(struct ip);
static const size_t ip6_size = sizeof(struct ip6_hdr);
static const size_t icmp6_size = sizeof(struct icmp6_hdr);
static const size_t ns_size = sizeof(struct nd_neighbor_solicit);
static const size_t opt_size = sizeof(struct nd_opt_hdr);

/* RFC 1071 */

static __inline__ uint16_t inet_checksum(void *data, int len, uint16_t prevsum)
{
	uint16_t *p = data;
	uint32_t checksum = prevsum ^ 0xFFFF;

	while(len >= 2) {
		checksum += *p++;
		len -= 2;
	}
	
	if(len)
		checksum += *(uint8_t *)p;

	while(checksum >> 16)
		checksum = (checksum & 0xFFFF) + (checksum >> 16);

	return ~checksum;
}

static __inline__ bool ratelimit(int frequency) {
	static time_t lasttime = 0;
	static int count = 0;
	
	if(lasttime == now) {
		if(++count > frequency)
			return true;
	} else {
		lasttime = now;
		count = 0;
	}

	return false;
}

static __inline__ bool checklength(node_t *source, vpn_packet_t *packet, length_t length) {
	if(packet->len < length) {
		ifdebug(TRAFFIC) logger(LOG_WARNING, _("Got too short packet from %s (%s)"), source->name, source->hostname);
		return false;
	} else
		return true;
}
	
static __inline__ void learn_mac(mac_t *address)
{
	subnet_t *subnet;
	avl_node_t *node;
	connection_t *c;

	cp();

	subnet = lookup_subnet_mac(address);

	/* If we don't know this MAC address yet, store it */

	if(!subnet) {
		ifdebug(TRAFFIC) logger(LOG_INFO, _("Learned new MAC address %hx:%hx:%hx:%hx:%hx:%hx"),
				   address->x[0], address->x[1], address->x[2], address->x[3],
				   address->x[4], address->x[5]);

		subnet = new_subnet();
		subnet->type = SUBNET_MAC;
		subnet->expires = now + macexpire;
		subnet->net.mac.address = *address;
		subnet_add(myself, subnet);

		/* And tell all other tinc daemons it's our MAC */

		for(node = connection_tree->head; node; node = node->next) {
			c = node->data;
			if(c->status.active)
				send_add_subnet(c, subnet);
		}
	}

	if(subnet->expires)
		subnet->expires = now + macexpire;
}

void age_subnets(void)
{
	subnet_t *s;
	connection_t *c;
	avl_node_t *node, *next, *node2;

	cp();

	for(node = myself->subnet_tree->head; node; node = next) {
		next = node->next;
		s = node->data;
		if(s->expires && s->expires < now) {
			ifdebug(TRAFFIC) {
				char netstr[MAXNETSTR];
				if(net2str(netstr, sizeof netstr, s))
					logger(LOG_INFO, _("Subnet %s expired"), netstr);
			}

			for(node2 = connection_tree->head; node2; node2 = node2->next) {
				c = node2->data;
				if(c->status.active)
					send_del_subnet(c, s);
			}

			subnet_del(myself, s);
		}
	}
}

static __inline__ void route_mac(node_t *source, vpn_packet_t *packet)
{
	subnet_t *subnet;

	cp();

	/* Learn source address */

	if(source == myself)
		learn_mac((mac_t *)(&packet->data[6]));

	/* Lookup destination address */

	subnet = lookup_subnet_mac((mac_t *)(&packet->data[0]));

	if(!subnet) {
		broadcast_packet(source, packet);
		return;
	}

	if(subnet->owner == source) {
		ifdebug(TRAFFIC) logger(LOG_WARNING, _("Packet looping back to %s (%s)!"), source->name, source->hostname);
		return;
	}

	send_packet(subnet->owner, packet);
}

/* RFC 792 */

static void route_ipv4_unreachable(node_t *source, vpn_packet_t *packet, uint8_t type, uint8_t code)
{
	struct ip ip = {0};
	struct icmp icmp = {0};
	
	struct in_addr ip_src;
	struct in_addr ip_dst;
	uint32_t oldlen;

	if(ratelimit(3))
		return;
	
	cp();

	/* Copy headers from packet into properly aligned structs on the stack */

	memcpy(&ip, packet->data + ether_size, ip_size);

	/* Remember original source and destination */
	
	ip_src = ip.ip_src;
	ip_dst = ip.ip_dst;

	oldlen = packet->len - ether_size;

	if(type == ICMP_DEST_UNREACH && code == ICMP_FRAG_NEEDED)
		icmp.icmp_nextmtu = htons(packet->len - ether_size);

	if(oldlen >= IP_MSS - ip_size - icmp_size)
		oldlen = IP_MSS - ip_size - icmp_size;
	
	/* Copy first part of original contents to ICMP message */
	
	memmove(packet->data + ether_size + ip_size + icmp_size, packet->data + ether_size, oldlen);

	/* Fill in IPv4 header */
	
	ip.ip_v = 4;
	ip.ip_hl = ip_size / 4;
	ip.ip_tos = 0;
	ip.ip_len = htons(ip_size + icmp_size + oldlen);
	ip.ip_id = 0;
	ip.ip_off = 0;
	ip.ip_ttl = 255;
	ip.ip_p = IPPROTO_ICMP;
	ip.ip_sum = 0;
	ip.ip_src = ip_dst;
	ip.ip_dst = ip_src;

	ip.ip_sum = inet_checksum(&ip, ip_size, ~0);
	
	/* Fill in ICMP header */
	
	icmp.icmp_type = type;
	icmp.icmp_code = code;
	icmp.icmp_cksum = 0;
	
	icmp.icmp_cksum = inet_checksum(&icmp, icmp_size, ~0);
	icmp.icmp_cksum = inet_checksum(packet->data + ether_size + ip_size + icmp_size, oldlen, icmp.icmp_cksum);

	/* Copy structs on stack back to packet */

	memcpy(packet->data + ether_size, &ip, ip_size);
	memcpy(packet->data + ether_size + ip_size, &icmp, icmp_size);
	
	packet->len = ether_size + ip_size + icmp_size + oldlen;

	send_packet(source, packet);
}

static __inline__ void route_ipv4_unicast(node_t *source, vpn_packet_t *packet)
{
	subnet_t *subnet;

	cp();

	subnet = lookup_subnet_ipv4((ipv4_t *) &packet->data[30]);

	if(!subnet) {
		ifdebug(TRAFFIC) logger(LOG_WARNING, _("Cannot route packet from %s (%s): unknown IPv4 destination address %d.%d.%d.%d"),
				source->name, source->hostname,
				packet->data[30],
				packet->data[31],
				packet->data[32],
				packet->data[33]);

		route_ipv4_unreachable(source, packet, ICMP_DEST_UNREACH, ICMP_NET_UNKNOWN);
		return;
	}
	
	if(subnet->owner == source) {
		ifdebug(TRAFFIC) logger(LOG_WARNING, _("Packet looping back to %s (%s)!"), source->name, source->hostname);
		return;
	}

	if(!subnet->owner->status.reachable)
		route_ipv4_unreachable(source, packet, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);

	if(subnet->owner->options & OPTION_PMTU_DISCOVERY && packet->len > subnet->owner->mtu && subnet->owner != myself) {
		ifdebug(TRAFFIC) logger(LOG_INFO, _("Packet for %s (%s) length %d larger than MTU %d"), subnet->owner->name, subnet->owner->hostname, packet->len, subnet->owner->mtu);
		packet->len = subnet->owner->mtu;
		route_ipv4_unreachable(source, packet, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED);
		return;
	}

	if(priorityinheritance)
		packet->priority = packet->data[15];

	send_packet(subnet->owner, packet);
}

static __inline__ void route_ipv4(node_t *source, vpn_packet_t *packet)
{
	cp();

	if(!checklength(source, packet, ether_size + ip_size))
		return;

	route_ipv4_unicast(source, packet);
}

/* RFC 2463 */

static void route_ipv6_unreachable(node_t *source, vpn_packet_t *packet, uint8_t type, uint8_t code)
{
	struct ip6_hdr ip6;
	struct icmp6_hdr icmp6 = {0};
	uint16_t checksum;	

	struct {
		struct in6_addr ip6_src;	/* source address */
		struct in6_addr ip6_dst;	/* destination address */
		uint32_t length;
		uint32_t next;
	} pseudo;

	if(ratelimit(3))
		return;
	
	cp();

	/* Copy headers from packet to structs on the stack */

	memcpy(&ip6, packet->data + ether_size, ip6_size);

	/* Remember original source and destination */
	
	pseudo.ip6_src = ip6.ip6_dst;
	pseudo.ip6_dst = ip6.ip6_src;

	pseudo.length = packet->len - ether_size;

	if(type == ICMP6_PACKET_TOO_BIG)
		icmp6.icmp6_mtu = htonl(pseudo.length);
	
	if(pseudo.length >= IP_MSS - ip6_size - icmp6_size)
		pseudo.length = IP_MSS - ip6_size - icmp6_size;
	
	/* Copy first part of original contents to ICMP message */
	
	memmove(packet->data + ether_size + ip6_size + icmp6_size, packet->data + ether_size, pseudo.length);

	/* Fill in IPv6 header */
	
	ip6.ip6_flow = htonl(0x60000000UL);
	ip6.ip6_plen = htons(icmp6_size + pseudo.length);
	ip6.ip6_nxt = IPPROTO_ICMPV6;
	ip6.ip6_hlim = 255;
	ip6.ip6_src = pseudo.ip6_src;
	ip6.ip6_dst = pseudo.ip6_dst;

	/* Fill in ICMP header */
	
	icmp6.icmp6_type = type;
	icmp6.icmp6_code = code;
	icmp6.icmp6_cksum = 0;

	/* Create pseudo header */
		
	pseudo.length = htonl(icmp6_size + pseudo.length);
	pseudo.next = htonl(IPPROTO_ICMPV6);

	/* Generate checksum */
	
	checksum = inet_checksum(&pseudo, sizeof(pseudo), ~0);
	checksum = inet_checksum(&icmp6, icmp6_size, checksum);
	checksum = inet_checksum(packet->data + ether_size + ip6_size + icmp6_size, ntohl(pseudo.length) - icmp6_size, checksum);

	icmp6.icmp6_cksum = checksum;

	/* Copy structs on stack back to packet */

	memcpy(packet->data + ether_size, &ip6, ip6_size);
	memcpy(packet->data + ether_size + ip6_size, &icmp6, icmp6_size);
	
	packet->len = ether_size + ip6_size + ntohl(pseudo.length);
	
	send_packet(source, packet);
}

static __inline__ void route_ipv6_unicast(node_t *source, vpn_packet_t *packet)
{
	subnet_t *subnet;

	cp();

	subnet = lookup_subnet_ipv6((ipv6_t *) &packet->data[38]);

	if(!subnet) {
		ifdebug(TRAFFIC) logger(LOG_WARNING, _("Cannot route packet from %s (%s): unknown IPv6 destination address %hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx"),
				source->name, source->hostname,
				ntohs(*(uint16_t *) &packet->data[38]),
				ntohs(*(uint16_t *) &packet->data[40]),
				ntohs(*(uint16_t *) &packet->data[42]),
				ntohs(*(uint16_t *) &packet->data[44]),
				ntohs(*(uint16_t *) &packet->data[46]),
				ntohs(*(uint16_t *) &packet->data[48]),
				ntohs(*(uint16_t *) &packet->data[50]),
				ntohs(*(uint16_t *) &packet->data[52]));

		route_ipv6_unreachable(source, packet, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_ADDR);
		return;
	}

	if(subnet->owner == source) {
		ifdebug(TRAFFIC) logger(LOG_WARNING, _("Packet looping back to %s (%s)!"), source->name, source->hostname);
		return;
	}

	if(!subnet->owner->status.reachable)
		route_ipv6_unreachable(source, packet, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOROUTE);
	
	if(subnet->owner->options & OPTION_PMTU_DISCOVERY && packet->len > subnet->owner->mtu && subnet->owner != myself) {
		ifdebug(TRAFFIC) logger(LOG_INFO, _("Packet for %s (%s) length %d larger than MTU %d"), subnet->owner->name, subnet->owner->hostname, packet->len, subnet->owner->mtu);
		packet->len = subnet->owner->mtu;
		route_ipv6_unreachable(source, packet, ICMP6_PACKET_TOO_BIG, 0);
		return;
	}

	send_packet(subnet->owner, packet);
}

/* RFC 2461 */

static void route_neighborsol(node_t *source, vpn_packet_t *packet)
{
	struct ip6_hdr ip6;
	struct nd_neighbor_solicit ns;
	struct nd_opt_hdr opt;
	subnet_t *subnet;
	uint16_t checksum;

	struct {
		struct in6_addr ip6_src;	/* source address */
		struct in6_addr ip6_dst;	/* destination address */
		uint32_t length;
		uint32_t next;
	} pseudo;

	cp();

	if(!checklength(source, packet, ether_size + ip6_size + ns_size + opt_size + ETH_ALEN))
		return;
	
	if(source != myself) {
		ifdebug(TRAFFIC) logger(LOG_WARNING, _("Got neighbor solicitation request from %s (%s) while in router mode!"), source->name, source->hostname);
		return;
	}

	/* Copy headers from packet to structs on the stack */

	memcpy(&ip6, packet->data + ether_size, ip6_size);
	memcpy(&ns, packet->data + ether_size + ip6_size, ns_size);
	memcpy(&opt, packet->data + ether_size + ip6_size + ns_size, opt_size);

	/* First, snatch the source address from the neighbor solicitation packet */

	if(overwrite_mac)
		memcpy(mymac.x, packet->data + ETH_ALEN, ETH_ALEN);

	/* Check if this is a valid neighbor solicitation request */

	if(ns.nd_ns_hdr.icmp6_type != ND_NEIGHBOR_SOLICIT ||
	   opt.nd_opt_type != ND_OPT_SOURCE_LINKADDR) {
		ifdebug(TRAFFIC) logger(LOG_WARNING, _("Cannot route packet: received unknown type neighbor solicitation request"));
		return;
	}

	/* Create pseudo header */

	pseudo.ip6_src = ip6.ip6_src;
	pseudo.ip6_dst = ip6.ip6_dst;
	pseudo.length = htonl(ns_size + opt_size + ETH_ALEN);
	pseudo.next = htonl(IPPROTO_ICMPV6);

	/* Generate checksum */

	checksum = inet_checksum(&pseudo, sizeof(pseudo), ~0);
	checksum = inet_checksum(&ns, ns_size, checksum);
	checksum = inet_checksum(&opt, opt_size, checksum);
	checksum = inet_checksum(packet->data + ether_size + ip6_size + ns_size + opt_size, ETH_ALEN, checksum);

	if(checksum) {
		ifdebug(TRAFFIC) logger(LOG_WARNING, _("Cannot route packet: checksum error for neighbor solicitation request"));
		return;
	}

	/* Check if the IPv6 address exists on the VPN */

	subnet = lookup_subnet_ipv6((ipv6_t *) &ns.nd_ns_target);

	if(!subnet) {
		ifdebug(TRAFFIC) logger(LOG_WARNING, _("Cannot route packet: neighbor solicitation request for unknown address %hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx"),
				   ntohs(((uint16_t *) &ns.nd_ns_target)[0]),
				   ntohs(((uint16_t *) &ns.nd_ns_target)[1]),
				   ntohs(((uint16_t *) &ns.nd_ns_target)[2]),
				   ntohs(((uint16_t *) &ns.nd_ns_target)[3]),
				   ntohs(((uint16_t *) &ns.nd_ns_target)[4]),
				   ntohs(((uint16_t *) &ns.nd_ns_target)[5]),
				   ntohs(((uint16_t *) &ns.nd_ns_target)[6]),
				   ntohs(((uint16_t *) &ns.nd_ns_target)[7]));

		return;
	}

	/* Check if it is for our own subnet */

	if(subnet->owner == myself)
		return;					/* silently ignore */

	/* Create neighbor advertation reply */

	memcpy(packet->data, packet->data + ETH_ALEN, ETH_ALEN);	/* copy destination address */
	packet->data[ETH_ALEN * 2 - 1] ^= 0xFF;	/* mangle source address so it looks like it's not from us */

	ip6.ip6_dst = ip6.ip6_src;			/* swap destination and source protocoll address */
	ip6.ip6_src = ns.nd_ns_target;

	memcpy(packet->data + ether_size + ip6_size + ns_size + opt_size, packet->data + ETH_ALEN, ETH_ALEN);	/* add fake source hard addr */

	ns.nd_ns_cksum = 0;
	ns.nd_ns_type = ND_NEIGHBOR_ADVERT;
	ns.nd_ns_reserved = htonl(0x40000000UL);	/* Set solicited flag */
	opt.nd_opt_type = ND_OPT_TARGET_LINKADDR;

	/* Create pseudo header */

	pseudo.ip6_src = ip6.ip6_src;
	pseudo.ip6_dst = ip6.ip6_dst;
	pseudo.length = htonl(ns_size + opt_size + ETH_ALEN);
	pseudo.next = htonl(IPPROTO_ICMPV6);

	/* Generate checksum */

	checksum = inet_checksum(&pseudo, sizeof(pseudo), ~0);
	checksum = inet_checksum(&ns, ns_size, checksum);
	checksum = inet_checksum(&opt, opt_size, checksum);
	checksum = inet_checksum(packet->data + ether_size + ip6_size + ns_size + opt_size, ETH_ALEN, checksum);

	ns.nd_ns_hdr.icmp6_cksum = checksum;

	/* Copy structs on stack back to packet */

	memcpy(packet->data + ether_size, &ip6, ip6_size);
	memcpy(packet->data + ether_size + ip6_size, &ns, ns_size);
	memcpy(packet->data + ether_size + ip6_size + ns_size, &opt, opt_size);

	send_packet(source, packet);
}

static __inline__ void route_ipv6(node_t *source, vpn_packet_t *packet)
{
	cp();

	if(!checklength(source, packet, ether_size + ip6_size))
		return;

	if(packet->data[20] == IPPROTO_ICMPV6 && checklength(source, packet, ether_size + ip6_size + icmp6_size) && packet->data[54] == ND_NEIGHBOR_SOLICIT) {
		route_neighborsol(source, packet);
		return;
	}

	route_ipv6_unicast(source, packet);
}

/* RFC 826 */

static void route_arp(node_t *source, vpn_packet_t *packet)
{
	struct ether_arp arp;
	subnet_t *subnet;
	struct in_addr addr;

	cp();

	if(!checklength(source, packet, ether_size + arp_size))
		return;

	if(source != myself) {
		ifdebug(TRAFFIC) logger(LOG_WARNING, _("Got ARP request from %s (%s) while in router mode!"), source->name, source->hostname);
		return;
	}

	/* First, snatch the source address from the ARP packet */

	if(overwrite_mac)
		memcpy(mymac.x, packet->data + ETH_ALEN, ETH_ALEN);

	/* Copy headers from packet to structs on the stack */

	memcpy(&arp, packet->data + ether_size, arp_size);

	/* Check if this is a valid ARP request */

	if(ntohs(arp.arp_hrd) != ARPHRD_ETHER || ntohs(arp.arp_pro) != ETH_P_IP ||
	   arp.arp_hln != ETH_ALEN || arp.arp_pln != sizeof(addr) || ntohs(arp.arp_op) != ARPOP_REQUEST) {
		ifdebug(TRAFFIC) logger(LOG_WARNING, _("Cannot route packet: received unknown type ARP request"));
		return;
	}

	/* Check if the IPv4 address exists on the VPN */

	subnet = lookup_subnet_ipv4((ipv4_t *) &arp.arp_tpa);

	if(!subnet) {
		ifdebug(TRAFFIC) logger(LOG_WARNING, _("Cannot route packet: ARP request for unknown address %d.%d.%d.%d"),
				   arp.arp_tpa[0], arp.arp_tpa[1], arp.arp_tpa[2],
				   arp.arp_tpa[3]);
		return;
	}

	/* Check if it is for our own subnet */

	if(subnet->owner == myself)
		return;					/* silently ignore */

	memcpy(packet->data, packet->data + ETH_ALEN, ETH_ALEN);	/* copy destination address */
	packet->data[ETH_ALEN * 2 - 1] ^= 0xFF;	/* mangle source address so it looks like it's not from us */

	memcpy(&addr, arp.arp_tpa, sizeof(addr));	/* save protocol addr */
	memcpy(arp.arp_tpa, arp.arp_spa, sizeof(addr));	/* swap destination and source protocol address */
	memcpy(arp.arp_spa, &addr, sizeof(addr));	/* ... */

	memcpy(arp.arp_tha, arp.arp_sha, ETH_ALEN);	/* set target hard/proto addr */
	memcpy(arp.arp_sha, packet->data + ETH_ALEN, ETH_ALEN);	/* add fake source hard addr */
	arp.arp_op = htons(ARPOP_REPLY);

	/* Copy structs on stack back to packet */

	memcpy(packet->data + ether_size, &arp, arp_size);

	send_packet(source, packet);
}

void route(node_t *source, vpn_packet_t *packet)
{
	cp();

	if(!checklength(source, packet, ether_size))
		return;

	switch (routing_mode) {
		case RMODE_ROUTER:
			{
				uint16_t type;

				type = ntohs(*((uint16_t *)(&packet->data[12])));
				switch (type) {
					case ETH_P_ARP:
						route_arp(source, packet);
						break;

					case ETH_P_IP:
						route_ipv4(source, packet);
						break;

					case ETH_P_IPV6:
						route_ipv6(source, packet);
						break;

					default:
						ifdebug(TRAFFIC) logger(LOG_WARNING, _("Cannot route packet from %s (%s): unknown type %hx"), source->name, source->hostname, type);
						break;
				}
			}
			break;

		case RMODE_SWITCH:
			route_mac(source, packet);
			break;

		case RMODE_HUB:
			broadcast_packet(source, packet);
			break;
	}
}
