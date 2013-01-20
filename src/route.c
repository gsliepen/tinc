/*
    route.c -- routing
    Copyright (C) 2000-2005 Ivo Timmermans,
                  2000-2013 Guus Sliepen <guus@tinc-vpn.org>

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

#include "system.h"

#include "connection.h"
#include "control_common.h"
#include "ethernet.h"
#include "ipv4.h"
#include "ipv6.h"
#include "logger.h"
#include "meta.h"
#include "net.h"
#include "protocol.h"
#include "route.h"
#include "subnet.h"
#include "utils.h"

rmode_t routing_mode = RMODE_ROUTER;
fmode_t forwarding_mode = FMODE_INTERNAL;
bmode_t broadcast_mode = BMODE_MST;
bool decrement_ttl = false;
bool directonly = false;
bool priorityinheritance = false;
int macexpire = 600;
bool overwrite_mac = false;
mac_t mymac = {{0xFE, 0xFD, 0, 0, 0, 0}};
bool pcap = false;

/* Sizes of various headers */

static const size_t ether_size = sizeof(struct ether_header);
static const size_t arp_size = sizeof(struct ether_arp);
static const size_t ip_size = sizeof(struct ip);
static const size_t icmp_size = sizeof(struct icmp) - sizeof(struct ip);
static const size_t ip6_size = sizeof(struct ip6_hdr);
static const size_t icmp6_size = sizeof(struct icmp6_hdr);
static const size_t ns_size = sizeof(struct nd_neighbor_solicit);
static const size_t opt_size = sizeof(struct nd_opt_hdr);

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

static timeout_t age_subnets_timeout;

/* RFC 1071 */

static uint16_t inet_checksum(void *data, int len, uint16_t prevsum) {
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

static bool ratelimit(int frequency) {
	static time_t lasttime = 0;
	static int count = 0;

	if(lasttime == now.tv_sec) {
		if(count >= frequency)
			return true;
	} else {
		lasttime = now.tv_sec;
		count = 0;
	}

	count++;
	return false;
}

static bool checklength(node_t *source, vpn_packet_t *packet, length_t length) {
	if(packet->len < length) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Got too short packet from %s (%s)", source->name, source->hostname);
		return false;
	} else
		return true;
}

static void clamp_mss(const node_t *source, const node_t *via, vpn_packet_t *packet) {
	if(!source || !via || !(via->options & OPTION_CLAMP_MSS))
		return;

	uint16_t mtu = source->mtu;
	if(via != myself && via->mtu < mtu)
		mtu = via->mtu;

	/* Find TCP header */
	int start = ether_size;
	uint16_t type = packet->data[12] << 8 | packet->data[13];

	if(type == ETH_P_8021Q) {
		start += 4;
		type = packet->data[16] << 8 | packet->data[17];
	}

	if(type == ETH_P_IP && packet->data[start + 9] == 6)
		start += (packet->data[start] & 0xf) * 4;
	else if(type == ETH_P_IPV6 && packet->data[start + 6] == 6)
		start += 40;
	else
		return;

	if(packet->len <= start + 20)
		return;

	/* Use data offset field to calculate length of options field */
	int len = ((packet->data[start + 12] >> 4) - 5) * 4;

	if(packet->len < start + 20 + len)
		return;

	/* Search for MSS option header */
	for(int i = 0; i < len;) {
		if(packet->data[start + 20 + i] == 0)
			break;

		if(packet->data[start + 20 + i] == 1) {
			i++;
			continue;
		}

		if(i > len - 2 || i > len - packet->data[start + 21 + i])
			break;

		if(packet->data[start + 20 + i] != 2) {
			if(packet->data[start + 21 + i] < 2)
				break;
			i += packet->data[start + 21 + i];
			continue;
		}

		if(packet->data[start + 21] != 4)
			break;

		/* Found it */
		uint16_t oldmss = packet->data[start + 22 + i] << 8 | packet->data[start + 23 + i];
		uint16_t newmss = mtu - start - 20;
		uint16_t csum = packet->data[start + 16] << 8 | packet->data[start + 17];

		if(oldmss <= newmss)
			break;

		logger(DEBUG_TRAFFIC, LOG_INFO, "Clamping MSS of packet from %s to %s to %d", source->name, via->name, newmss);

		/* Update the MSS value and the checksum */
		packet->data[start + 22 + i] = newmss >> 8;
		packet->data[start + 23 + i] = newmss & 0xff;
		csum ^= 0xffff;
		csum -= oldmss;
		csum += newmss;
		csum ^= 0xffff;
		packet->data[start + 16] = csum >> 8;
		packet->data[start + 17] = csum & 0xff;
		break;
	}
}

static void swap_mac_addresses(vpn_packet_t *packet) {
	mac_t tmp;
	memcpy(&tmp, &packet->data[0], sizeof tmp);
	memcpy(&packet->data[0], &packet->data[6], sizeof tmp);
	memcpy(&packet->data[6], &tmp, sizeof tmp);
}

static void age_subnets(void *data) {
	bool left = false;

	for splay_each(subnet_t, s, myself->subnet_tree) {
		if(s->expires && s->expires < now.tv_sec) {
			if(debug_level >= DEBUG_TRAFFIC) {
				char netstr[MAXNETSTR];
				if(net2str(netstr, sizeof netstr, s))
					logger(DEBUG_TRAFFIC, LOG_INFO, "Subnet %s expired", netstr);
			}

			for list_each(connection_t, c, connection_list)
				if(c->status.active)
					send_del_subnet(c, s);

			subnet_del(myself, s);
		} else {
			if(s->expires)
				left = true;
		}
	}

	if(left)
		timeout_set(&age_subnets_timeout, &(struct timeval){10, rand() % 100000});
}

static void learn_mac(mac_t *address) {
	subnet_t *subnet = lookup_subnet_mac(myself, address);

	/* If we don't know this MAC address yet, store it */

	if(!subnet) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Learned new MAC address %hx:%hx:%hx:%hx:%hx:%hx",
				   address->x[0], address->x[1], address->x[2], address->x[3],
				   address->x[4], address->x[5]);

		subnet = new_subnet();
		subnet->type = SUBNET_MAC;
		subnet->expires = time(NULL) + macexpire;
		subnet->net.mac.address = *address;
		subnet->weight = 10;
		subnet_add(myself, subnet);
		subnet_update(myself, subnet, true);

		/* And tell all other tinc daemons it's our MAC */

		for list_each(connection_t, c, connection_list)
			if(c->status.active)
				send_add_subnet(c, subnet);

		timeout_add(&age_subnets_timeout, age_subnets, NULL, &(struct timeval){10, rand() % 100000});
	} else {
		if(subnet->expires)
			subnet->expires = time(NULL) + macexpire;
	}
}

/* RFC 792 */

static void route_ipv4_unreachable(node_t *source, vpn_packet_t *packet, length_t ether_size, uint8_t type, uint8_t code) {
	struct ip ip = {0};
	struct icmp icmp = {0};

	struct in_addr ip_src;
	struct in_addr ip_dst;
	uint32_t oldlen;

	if(ratelimit(3))
		return;

	/* Swap Ethernet source and destination addresses */

	swap_mac_addresses(packet);

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

/* RFC 791 */

static void fragment_ipv4_packet(node_t *dest, vpn_packet_t *packet, length_t ether_size) {
	struct ip ip;
	vpn_packet_t fragment;
	int len, maxlen, todo;
	uint8_t *offset;
	uint16_t ip_off, origf;

	memcpy(&ip, packet->data + ether_size, ip_size);
	fragment.priority = packet->priority;

	if(ip.ip_hl != ip_size / 4)
		return;

	todo = ntohs(ip.ip_len) - ip_size;

	if(ether_size + ip_size + todo != packet->len) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Length of packet (%d) doesn't match length in IPv4 header (%d)", packet->len, (int)(ether_size + ip_size + todo));
		return;
	}

	logger(DEBUG_TRAFFIC, LOG_INFO, "Fragmenting packet of %d bytes to %s (%s)", packet->len, dest->name, dest->hostname);

	offset = packet->data + ether_size + ip_size;
	maxlen = (dest->mtu - ether_size - ip_size) & ~0x7;
	ip_off = ntohs(ip.ip_off);
	origf = ip_off & ~IP_OFFMASK;
	ip_off &= IP_OFFMASK;

	while(todo) {
		len = todo > maxlen ? maxlen : todo;
		memcpy(fragment.data + ether_size + ip_size, offset, len);
		todo -= len;
		offset += len;

		ip.ip_len = htons(ip_size + len);
		ip.ip_off = htons(ip_off | origf | (todo ? IP_MF : 0));
		ip.ip_sum = 0;
		ip.ip_sum = inet_checksum(&ip, ip_size, ~0);
		memcpy(fragment.data, packet->data, ether_size);
		memcpy(fragment.data + ether_size, &ip, ip_size);
		fragment.len = ether_size + ip_size + len;

		send_packet(dest, &fragment);

		ip_off += len / 8;
	}
}

static void route_ipv4_unicast(node_t *source, vpn_packet_t *packet) {
	subnet_t *subnet;
	node_t *via;
	ipv4_t dest;

	memcpy(&dest, &packet->data[30], sizeof dest);
	subnet = lookup_subnet_ipv4(&dest);

	if(!subnet) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Cannot route packet from %s (%s): unknown IPv4 destination address %d.%d.%d.%d",
				source->name, source->hostname,
				dest.x[0],
				dest.x[1],
				dest.x[2],
				dest.x[3]);

		route_ipv4_unreachable(source, packet, ether_size, ICMP_DEST_UNREACH, ICMP_NET_UNKNOWN);
		return;
	}

	if(subnet->owner == source) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Packet looping back to %s (%s)!", source->name, source->hostname);
		return;
	}

	if(!subnet->owner->status.reachable)
		return route_ipv4_unreachable(source, packet, ether_size, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);

	if(forwarding_mode == FMODE_OFF && source != myself && subnet->owner != myself)
		return route_ipv4_unreachable(source, packet, ether_size, ICMP_DEST_UNREACH, ICMP_NET_ANO);

	if(priorityinheritance)
		packet->priority = packet->data[15];

	via = (subnet->owner->via == myself) ? subnet->owner->nexthop : subnet->owner->via;

	if(via == source) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "Routing loop for packet from %s (%s)!", source->name, source->hostname);
		return;
	}

	if(directonly && subnet->owner != via)
		return route_ipv4_unreachable(source, packet, ether_size, ICMP_DEST_UNREACH, ICMP_NET_ANO);

	if(via && packet->len > MAX(via->mtu, 590) && via != myself) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Packet for %s (%s) length %d larger than MTU %d", subnet->owner->name, subnet->owner->hostname, packet->len, via->mtu);
		if(packet->data[20] & 0x40) {
			packet->len = MAX(via->mtu, 590);
			route_ipv4_unreachable(source, packet, ether_size, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED);
		} else {
			fragment_ipv4_packet(via, packet, ether_size);
		}

		return;
	}

	clamp_mss(source, via, packet);

	send_packet(subnet->owner, packet);
}

static void route_ipv4(node_t *source, vpn_packet_t *packet) {
	if(!checklength(source, packet, ether_size + ip_size))
		return;

	if(broadcast_mode && (((packet->data[30] & 0xf0) == 0xe0) || (
			packet->data[30] == 255 &&
			packet->data[31] == 255 &&
			packet->data[32] == 255 &&
			packet->data[33] == 255)))
		broadcast_packet(source, packet);
	else
		route_ipv4_unicast(source, packet);
}

/* RFC 2463 */

static void route_ipv6_unreachable(node_t *source, vpn_packet_t *packet, length_t ether_size, uint8_t type, uint8_t code) {
	struct ip6_hdr ip6;
	struct icmp6_hdr icmp6 = {0};
	uint16_t checksum;

	struct {
		struct in6_addr ip6_src;        /* source address */
		struct in6_addr ip6_dst;        /* destination address */
		uint32_t length;
		uint32_t next;
	} pseudo;

	if(ratelimit(3))
		return;

	/* Swap Ethernet source and destination addresses */

	swap_mac_addresses(packet);

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

	checksum = inet_checksum(&pseudo, sizeof pseudo, ~0);
	checksum = inet_checksum(&icmp6, icmp6_size, checksum);
	checksum = inet_checksum(packet->data + ether_size + ip6_size + icmp6_size, ntohl(pseudo.length) - icmp6_size, checksum);

	icmp6.icmp6_cksum = checksum;

	/* Copy structs on stack back to packet */

	memcpy(packet->data + ether_size, &ip6, ip6_size);
	memcpy(packet->data + ether_size + ip6_size, &icmp6, icmp6_size);

	packet->len = ether_size + ip6_size + ntohl(pseudo.length);

	send_packet(source, packet);
}

static void route_ipv6_unicast(node_t *source, vpn_packet_t *packet) {
	subnet_t *subnet;
	node_t *via;
	ipv6_t dest;

	memcpy(&dest, &packet->data[38], sizeof dest);
	subnet = lookup_subnet_ipv6(&dest);

	if(!subnet) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Cannot route packet from %s (%s): unknown IPv6 destination address %hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx",
				source->name, source->hostname,
				ntohs(dest.x[0]),
				ntohs(dest.x[1]),
				ntohs(dest.x[2]),
				ntohs(dest.x[3]),
				ntohs(dest.x[4]),
				ntohs(dest.x[5]),
				ntohs(dest.x[6]),
				ntohs(dest.x[7]));

		route_ipv6_unreachable(source, packet, ether_size, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_ADDR);
		return;
	}

	if(subnet->owner == source) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Packet looping back to %s (%s)!", source->name, source->hostname);
		return;
	}

	if(!subnet->owner->status.reachable)
		return route_ipv6_unreachable(source, packet, ether_size, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOROUTE);

	if(forwarding_mode == FMODE_OFF && source != myself && subnet->owner != myself)
		return route_ipv6_unreachable(source, packet, ether_size, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_ADMIN);

	via = (subnet->owner->via == myself) ? subnet->owner->nexthop : subnet->owner->via;

	if(via == source) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "Routing loop for packet from %s (%s)!", source->name, source->hostname);
		return;
	}

	if(directonly && subnet->owner != via)
		return route_ipv6_unreachable(source, packet, ether_size, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_ADMIN);

	if(via && packet->len > MAX(via->mtu, 1294) && via != myself) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Packet for %s (%s) length %d larger than MTU %d", subnet->owner->name, subnet->owner->hostname, packet->len, via->mtu);
		packet->len = MAX(via->mtu, 1294);
		route_ipv6_unreachable(source, packet, ether_size, ICMP6_PACKET_TOO_BIG, 0);
		return;
	}

	clamp_mss(source, via, packet);

	send_packet(subnet->owner, packet);
}

/* RFC 2461 */

static void route_neighborsol(node_t *source, vpn_packet_t *packet) {
	struct ip6_hdr ip6;
	struct nd_neighbor_solicit ns;
	struct nd_opt_hdr opt;
	subnet_t *subnet;
	uint16_t checksum;
	bool has_opt;

	struct {
		struct in6_addr ip6_src;
		struct in6_addr ip6_dst;
		uint32_t length;
		uint32_t next;
	} pseudo;

	if(!checklength(source, packet, ether_size + ip6_size + ns_size))
		return;

	has_opt = packet->len >= ether_size + ip6_size + ns_size + opt_size + ETH_ALEN;

	if(source != myself) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Got neighbor solicitation request from %s (%s) while in router mode!", source->name, source->hostname);
		return;
	}

	/* Copy headers from packet to structs on the stack */

	memcpy(&ip6, packet->data + ether_size, ip6_size);
	memcpy(&ns, packet->data + ether_size + ip6_size, ns_size);
	if(has_opt)
		memcpy(&opt, packet->data + ether_size + ip6_size + ns_size, opt_size);

	/* First, snatch the source address from the neighbor solicitation packet */

	if(overwrite_mac)
		memcpy(mymac.x, packet->data + ETH_ALEN, ETH_ALEN);

	/* Check if this is a valid neighbor solicitation request */

	if(ns.nd_ns_hdr.icmp6_type != ND_NEIGHBOR_SOLICIT ||
	   (has_opt && opt.nd_opt_type != ND_OPT_SOURCE_LINKADDR)) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Cannot route packet: received unknown type neighbor solicitation request");
		return;
	}

	/* Create pseudo header */

	pseudo.ip6_src = ip6.ip6_src;
	pseudo.ip6_dst = ip6.ip6_dst;
	if(has_opt)
		pseudo.length = htonl(ns_size + opt_size + ETH_ALEN);
	else
		pseudo.length = htonl(ns_size);
	pseudo.next = htonl(IPPROTO_ICMPV6);

	/* Generate checksum */

	checksum = inet_checksum(&pseudo, sizeof pseudo, ~0);
	checksum = inet_checksum(&ns, ns_size, checksum);
	if(has_opt) {
		checksum = inet_checksum(&opt, opt_size, checksum);
		checksum = inet_checksum(packet->data + ether_size + ip6_size + ns_size + opt_size, ETH_ALEN, checksum);
	}

	if(checksum) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Cannot route packet: checksum error for neighbor solicitation request");
		return;
	}

	/* Check if the IPv6 address exists on the VPN */

	subnet = lookup_subnet_ipv6((ipv6_t *) &ns.nd_ns_target);

	if(!subnet) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Cannot route packet: neighbor solicitation request for unknown address %hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx",
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
		return;                                          /* silently ignore */

	/* Create neighbor advertation reply */

	memcpy(packet->data, packet->data + ETH_ALEN, ETH_ALEN); /* copy destination address */
	packet->data[ETH_ALEN * 2 - 1] ^= 0xFF;                  /* mangle source address so it looks like it's not from us */

	ip6.ip6_dst = ip6.ip6_src;                               /* swap destination and source protocoll address */
	ip6.ip6_src = ns.nd_ns_target;

	if(has_opt)
		memcpy(packet->data + ether_size + ip6_size + ns_size + opt_size, packet->data + ETH_ALEN, ETH_ALEN);   /* add fake source hard addr */

	ns.nd_ns_cksum = 0;
	ns.nd_ns_type = ND_NEIGHBOR_ADVERT;
	ns.nd_ns_reserved = htonl(0x40000000UL);                 /* Set solicited flag */
	opt.nd_opt_type = ND_OPT_TARGET_LINKADDR;

	/* Create pseudo header */

	pseudo.ip6_src = ip6.ip6_src;
	pseudo.ip6_dst = ip6.ip6_dst;
	if(has_opt)
		pseudo.length = htonl(ns_size + opt_size + ETH_ALEN);
	else
		pseudo.length = htonl(ns_size);
	pseudo.next = htonl(IPPROTO_ICMPV6);

	/* Generate checksum */

	checksum = inet_checksum(&pseudo, sizeof pseudo, ~0);
	checksum = inet_checksum(&ns, ns_size, checksum);
	if(has_opt) {
		checksum = inet_checksum(&opt, opt_size, checksum);
		checksum = inet_checksum(packet->data + ether_size + ip6_size + ns_size + opt_size, ETH_ALEN, checksum);
	}

	ns.nd_ns_hdr.icmp6_cksum = checksum;

	/* Copy structs on stack back to packet */

	memcpy(packet->data + ether_size, &ip6, ip6_size);
	memcpy(packet->data + ether_size + ip6_size, &ns, ns_size);
	if(has_opt)
		memcpy(packet->data + ether_size + ip6_size + ns_size, &opt, opt_size);

	send_packet(source, packet);
}

static void route_ipv6(node_t *source, vpn_packet_t *packet) {
	if(!checklength(source, packet, ether_size + ip6_size))
		return;

	if(packet->data[20] == IPPROTO_ICMPV6 && checklength(source, packet, ether_size + ip6_size + icmp6_size) && packet->data[54] == ND_NEIGHBOR_SOLICIT) {
		route_neighborsol(source, packet);
		return;
	}

	if(broadcast_mode && packet->data[38] == 255)
		broadcast_packet(source, packet);
	else
		route_ipv6_unicast(source, packet);
}

/* RFC 826 */

static void route_arp(node_t *source, vpn_packet_t *packet) {
	struct ether_arp arp;
	subnet_t *subnet;
	struct in_addr addr;

	if(!checklength(source, packet, ether_size + arp_size))
		return;

	if(source != myself) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Got ARP request from %s (%s) while in router mode!", source->name, source->hostname);
		return;
	}

	/* First, snatch the source address from the ARP packet */

	if(overwrite_mac)
		memcpy(mymac.x, packet->data + ETH_ALEN, ETH_ALEN);

	/* Copy headers from packet to structs on the stack */

	memcpy(&arp, packet->data + ether_size, arp_size);

	/* Check if this is a valid ARP request */

	if(ntohs(arp.arp_hrd) != ARPHRD_ETHER || ntohs(arp.arp_pro) != ETH_P_IP ||
	   arp.arp_hln != ETH_ALEN || arp.arp_pln != sizeof addr || ntohs(arp.arp_op) != ARPOP_REQUEST) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Cannot route packet: received unknown type ARP request");
		return;
	}

	/* Check if the IPv4 address exists on the VPN */

	subnet = lookup_subnet_ipv4((ipv4_t *) &arp.arp_tpa);

	if(!subnet) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Cannot route packet: ARP request for unknown address %d.%d.%d.%d",
				   arp.arp_tpa[0], arp.arp_tpa[1], arp.arp_tpa[2],
				   arp.arp_tpa[3]);
		return;
	}

	/* Check if it is for our own subnet */

	if(subnet->owner == myself)
		return;                                          /* silently ignore */

	memcpy(packet->data, packet->data + ETH_ALEN, ETH_ALEN); /* copy destination address */
	packet->data[ETH_ALEN * 2 - 1] ^= 0xFF;                  /* mangle source address so it looks like it's not from us */

	memcpy(&addr, arp.arp_tpa, sizeof addr);                 /* save protocol addr */
	memcpy(arp.arp_tpa, arp.arp_spa, sizeof addr);           /* swap destination and source protocol address */
	memcpy(arp.arp_spa, &addr, sizeof addr);                 /* ... */

	memcpy(arp.arp_tha, arp.arp_sha, ETH_ALEN);              /* set target hard/proto addr */
	memcpy(arp.arp_sha, packet->data + ETH_ALEN, ETH_ALEN);  /* add fake source hard addr */
	arp.arp_op = htons(ARPOP_REPLY);

	/* Copy structs on stack back to packet */

	memcpy(packet->data + ether_size, &arp, arp_size);

	send_packet(source, packet);
}

static void route_mac(node_t *source, vpn_packet_t *packet) {
	subnet_t *subnet;
	mac_t dest;

	/* Learn source address */

	if(source == myself) {
		mac_t src;
		memcpy(&src, &packet->data[6], sizeof src);
		learn_mac(&src);
	}

	/* Lookup destination address */

	memcpy(&dest, &packet->data[0], sizeof dest);
	subnet = lookup_subnet_mac(NULL, &dest);

	if(!subnet) {
		broadcast_packet(source, packet);
		return;
	}

	if(subnet->owner == source) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Packet looping back to %s (%s)!", source->name, source->hostname);
		return;
	}

	if(forwarding_mode == FMODE_OFF && source != myself && subnet->owner != myself)
		return;

	uint16_t type = packet->data[12] << 8 | packet->data[13];

	if(priorityinheritance && type == ETH_P_IP && packet->len >= ether_size + ip_size)
		packet->priority = packet->data[15];

	// Handle packets larger than PMTU

	node_t *via = (subnet->owner->via == myself) ? subnet->owner->nexthop : subnet->owner->via;

	if(directonly && subnet->owner != via)
		return;

	if(via && packet->len > via->mtu && via != myself) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Packet for %s (%s) length %d larger than MTU %d", subnet->owner->name, subnet->owner->hostname, packet->len, via->mtu);
		length_t ethlen = 14;

		if(type == ETH_P_8021Q) {
			type = packet->data[16] << 8 | packet->data[17];
			ethlen += 4;
		}

		if(type == ETH_P_IP && packet->len > 576 + ethlen) {
			if(packet->data[6 + ethlen] & 0x40) {
				packet->len = via->mtu;
				route_ipv4_unreachable(source, packet, ethlen, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED);
			} else {
				fragment_ipv4_packet(via, packet, ethlen);
			}
			return;
		} else if(type == ETH_P_IPV6 && packet->len > 1280 + ethlen) {
			packet->len = via->mtu;
			route_ipv6_unreachable(source, packet, ethlen, ICMP6_PACKET_TOO_BIG, 0);
			return;
		}
	}

	clamp_mss(source, via, packet);

	send_packet(subnet->owner, packet);
}

static void send_pcap(vpn_packet_t *packet) {
	pcap = false;

	for list_each(connection_t, c, connection_list) {
		if(!c->status.pcap)
			continue;

		pcap = true;
		int len = packet->len;
		if(c->outmaclength && c->outmaclength < len)
			len = c->outmaclength;

		if(send_request(c, "%d %d %d", CONTROL, REQ_PCAP, len))
			send_meta(c, (char *)packet->data, len);
	}
}

static bool do_decrement_ttl(node_t *source, vpn_packet_t *packet) {
	uint16_t type = packet->data[12] << 8 | packet->data[13];
	length_t ethlen = ether_size;

	if(type == ETH_P_8021Q) {
		type = packet->data[16] << 8 | packet->data[17];
		ethlen += 4;
	}

	switch (type) {
		case ETH_P_IP:
			if(!checklength(source, packet, ethlen + ip_size))
				return false;

			if(packet->data[ethlen + 8] < 1) {
				if(packet->data[ethlen + 11] != IPPROTO_ICMP || packet->data[ethlen + 32] != ICMP_TIME_EXCEEDED)
					route_ipv4_unreachable(source, packet, ethlen, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
				return false;
			}

			uint16_t old = packet->data[ethlen + 8] << 8 | packet->data[ethlen + 9];
			packet->data[ethlen + 8]--;
			uint16_t new = packet->data[ethlen + 8] << 8 | packet->data[ethlen + 9];

			uint32_t checksum = packet->data[ethlen + 10] << 8 | packet->data[ethlen + 11];
			checksum += old + (~new & 0xFFFF);
			while(checksum >> 16)
				checksum = (checksum & 0xFFFF) + (checksum >> 16);
			packet->data[ethlen + 10] = checksum >> 8;
			packet->data[ethlen + 11] = checksum & 0xff;

			return true;

		case ETH_P_IPV6:
			if(!checklength(source, packet, ethlen + ip6_size))
				return false;

			if(packet->data[ethlen + 7] < 1) {
				if(packet->data[ethlen + 6] != IPPROTO_ICMPV6 || packet->data[ethlen + 40] != ICMP6_TIME_EXCEEDED)
					route_ipv6_unreachable(source, packet, ethlen, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT);
				return false;
			}

			packet->data[ethlen + 7]--;

			return true;

		default:
			return true;
	}
}

void route(node_t *source, vpn_packet_t *packet) {
	if(pcap)
		send_pcap(packet);

	if(forwarding_mode == FMODE_KERNEL && source != myself) {
		send_packet(myself, packet);
		return;
	}

	if(!checklength(source, packet, ether_size))
		return;

	if(decrement_ttl && source != myself)
		if(!do_decrement_ttl(source, packet))
			return;

	uint16_t type = packet->data[12] << 8 | packet->data[13];

	switch (routing_mode) {
		case RMODE_ROUTER:
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
					logger(DEBUG_TRAFFIC, LOG_WARNING, "Cannot route packet from %s (%s): unknown type %hx", source->name, source->hostname, type);
					break;
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
