/*
    pong.c -- ICMP echo reply generator
    Copyright (C) 2013-2017 Guus Sliepen <guus@tinc-vpn.org>

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

#include "../src/system.h"

#include "../src/ethernet.h"

uint8_t mymac[6] = {6, 5, 5, 6, 5, 5};

static ssize_t do_arp(uint8_t *buf, ssize_t len, struct sockaddr_in *in) {
	struct ether_arp arp;
	memcpy(&arp, buf + 14, sizeof arp);

	// Is it a valid ARP request?
	if(ntohs(arp.arp_hrd) != ARPHRD_ETHER || ntohs(arp.arp_pro) != ETH_P_IP || arp.arp_hln != ETH_ALEN || arp.arp_pln != sizeof in->sin_addr.s_addr || ntohs(arp.arp_op) != ARPOP_REQUEST)
		return 0;

	// Does it match our address?
	if(memcmp(&in->sin_addr.s_addr, arp.arp_tpa, 4))
		return 0;

	// Swap addresses
	memcpy(buf, buf + 6, 6);
	memcpy(buf + 6, mymac, 6);

	arp.arp_op = htons(ARPOP_REPLY);
	memcpy(arp.arp_tpa, arp.arp_spa, sizeof arp.arp_tpa);
	memcpy(arp.arp_tha, arp.arp_sha, sizeof arp.arp_tha);
	memcpy(arp.arp_spa, &in->sin_addr.s_addr, sizeof in->sin_addr.s_addr);
	memcpy(arp.arp_sha, mymac, 6);

	memcpy(buf + 14, &arp, sizeof arp);

	return len;
}

static ssize_t do_ipv4(uint8_t *buf, ssize_t len, struct sockaddr_in *in) {
	struct ip ip;
	struct icmp icmp;

	// Does it match our address?
	if(memcmp(buf, mymac, 6))
		return 0;

	memcpy(&ip, buf + 14, sizeof ip);
	if(memcmp(&ip.ip_dst, &in->sin_addr.s_addr, 4))
		return 0;

	// Is it an ICMP echo request?
	if(ip.ip_p != IPPROTO_ICMP)
		return 0;

	memcpy(&icmp, buf + 14 + sizeof ip, sizeof icmp);
	if(icmp.icmp_type != ICMP_ECHO)
		return 0;

	// Return an echo reply
	memcpy(buf, buf + 6, 6);
	memcpy(buf + 6, mymac, 6);

	ip.ip_dst = ip.ip_src;
	memcpy(&ip.ip_src, &in->sin_addr.s_addr, 4);

	icmp.icmp_type = ICMP_ECHOREPLY;

	memcpy(buf + 14, &ip, sizeof ip);
	memcpy(buf + 14 + sizeof ip, &icmp, sizeof icmp);

	return len;
}

static ssize_t do_ipv6(uint8_t *buf, ssize_t len, struct sockaddr_in6 *in) {
	return 0;
}

int main(int argc, char *argv[]) {
	if(argc != 4) {
		fprintf(stderr, "Usage: %s <multicast address> <port> <ping address>\n", argv[0]);
		return 1;
	}

	struct addrinfo hints = {}, *ai = NULL;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_ADDRCONFIG;

	errno = ENOENT;
	if(getaddrinfo(argv[1], argv[2], &hints, &ai) || !ai) {
		fprintf(stderr, "Could not resolve %s port %s: %s\n", argv[1], argv[2], strerror(errno));
		return 1;
	}

	int fd;
	fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if(!fd) {
		fprintf(stderr, "Could not create socket: %s\n", strerror(errno));
		return 1;
	}

	static const int one = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof one);

	if(bind(fd, ai->ai_addr, ai->ai_addrlen)) {
		fprintf(stderr, "Could not bind socket: %s\n", strerror(errno));
		return 1;
	}

	switch(ai->ai_family) {
		case AF_INET: {
			struct ip_mreq mreq;
			struct sockaddr_in in;
			memcpy(&in, ai->ai_addr, sizeof in);
			mreq.imr_multiaddr.s_addr = in.sin_addr.s_addr;
			mreq.imr_interface.s_addr = htonl(INADDR_ANY);
			if(setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&mreq, sizeof mreq)) {
				fprintf(stderr, "Cannot join multicast group: %s\n", strerror(errno));
				return 1;
			}
#ifdef IP_MULTICAST_LOOP
			setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, (const void *)&one, sizeof one);
#endif
		} break;

#ifdef IPV6_JOIN_GROUP
		case AF_INET6: {
			struct ipv6_mreq mreq;
			struct sockaddr_in6 in6;
			memcpy(&in6, ai->ai_addr, sizeof in6);
			memcpy(&mreq.ipv6mr_multiaddr, &in6.sin6_addr, sizeof mreq.ipv6mr_multiaddr);
			mreq.ipv6mr_interface = in6.sin6_scope_id;
			if(setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, (void *)&mreq, sizeof mreq)) {
				fprintf(stderr, "Cannot join multicast group: %s\n", strerror(errno));
				return 1;
			}
#ifdef IPV6_MULTICAST_LOOP
			setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (const void *)&one, sizeof one);
#endif
		} break;
#endif

		default:
			fprintf(stderr, "Multicast for address family %x unsupported\n", ai->ai_family);
			return 1;
	}

	errno = ENOENT;
	struct addrinfo *ai2 = NULL;
	if(getaddrinfo(argv[3], NULL, &hints, &ai2) || !ai2) {
		fprintf(stderr, "Could not resolve %s: %s\n", argv[3], strerror(errno));
		return 1;
	}

	while(true) {
		uint8_t buf[10000];
		struct sockaddr src;
		socklen_t srclen;
		ssize_t len = recvfrom(fd, buf, sizeof buf, 0, &src, &srclen);
		if(len <= 0)
			break;

		// Ignore short packets.
		if(len < 14)
			continue;

		uint16_t type = buf[12] << 8 | buf[13];

		if(ai2->ai_family == AF_INET && type == ETH_P_IP)
			len = do_ipv4(buf, len, (struct sockaddr_in *)ai2->ai_addr);
		else if(ai2->ai_family == AF_INET && type == ETH_P_ARP)
			len = do_arp(buf, len, (struct sockaddr_in *)ai2->ai_addr);
		else if(ai2->ai_family == AF_INET6 && type == ETH_P_IPV6)
			len = do_ipv6(buf, len, (struct sockaddr_in6 *)ai2->ai_addr);
		else
			continue;

		if(len > 0)
			sendto(fd, buf, len, 0, ai->ai_addr, ai->ai_addrlen);
	}

	return 0;
}
