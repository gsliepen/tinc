/*
    device.c -- multicast socket
    Copyright (C) 2002-2005 Ivo Timmermans,
                  2002-2014 Guus Sliepen <guus@tinc-vpn.org>

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

#include "conf.h"
#include "device.h"
#include "net.h"
#include "logger.h"
#include "netutl.h"
#include "utils.h"
#include "route.h"
#include "xalloc.h"

static const char *device_info = "multicast socket";

static uint64_t device_total_in = 0;
static uint64_t device_total_out = 0;

static struct addrinfo *ai = NULL;
static mac_t ignore_src = {{0}};

static bool setup_device(void) {
	char *host;
	char *port;
	char *space;
	int ttl = 1;

	get_config_string(lookup_config(config_tree, "Interface"), &iface);

	if(!get_config_string(lookup_config(config_tree, "Device"), &device)) {
		logger(LOG_ERR, "Device variable required for %s", device_info);
		return false;
	}

	host = xstrdup(device);
	space = strchr(host, ' ');

	if(!space) {
		logger(LOG_ERR, "Port number required for %s", device_info);
		free(host);
		return false;
	}

	*space++ = 0;
	port = space;
	space = strchr(port, ' ');

	if(space) {
		*space++ = 0;
		ttl = atoi(space);
	}

	ai = str2addrinfo(host, port, SOCK_DGRAM);

	if(!ai) {
		free(host);
		return false;
	}

	device_fd = socket(ai->ai_family, SOCK_DGRAM, IPPROTO_UDP);

	if(device_fd < 0) {
		logger(LOG_ERR, "Creating socket failed: %s", sockstrerror(sockerrno));
		free(host);
		return false;
	}

#ifdef FD_CLOEXEC
	fcntl(device_fd, F_SETFD, FD_CLOEXEC);
#endif

	static const int one = 1;
	setsockopt(device_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof(one));

	if(bind(device_fd, ai->ai_addr, ai->ai_addrlen)) {
		closesocket(device_fd);
		logger(LOG_ERR, "Can't bind to %s %s: %s", host, port, sockstrerror(sockerrno));
		free(host);
		return false;
	}

	switch(ai->ai_family) {
#ifdef IP_ADD_MEMBERSHIP

	case AF_INET: {
		struct ip_mreq mreq;
		struct sockaddr_in in;
		memcpy(&in, ai->ai_addr, sizeof(in));
		mreq.imr_multiaddr.s_addr = in.sin_addr.s_addr;
		mreq.imr_interface.s_addr = htonl(INADDR_ANY);

		if(setsockopt(device_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq))) {
			logger(LOG_ERR, "Cannot join multicast group %s %s: %s", host, port, sockstrerror(sockerrno));
			closesocket(device_fd);
			free(host);
			return false;
		}

#ifdef IP_MULTICAST_LOOP
		setsockopt(device_fd, IPPROTO_IP, IP_MULTICAST_LOOP, (const void *)&one, sizeof(one));
#endif
#ifdef IP_MULTICAST_TTL
		setsockopt(device_fd, IPPROTO_IP, IP_MULTICAST_TTL, (void *)&ttl, sizeof(ttl));
#endif
	}
	break;
#endif

#ifdef IPV6_JOIN_GROUP

	case AF_INET6: {
		struct ipv6_mreq mreq;
		struct sockaddr_in6 in6;
		memcpy(&in6, ai->ai_addr, sizeof(in6));
		memcpy(&mreq.ipv6mr_multiaddr, &in6.sin6_addr, sizeof(mreq.ipv6mr_multiaddr));
		mreq.ipv6mr_interface = in6.sin6_scope_id;

		if(setsockopt(device_fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, (void *)&mreq, sizeof(mreq))) {
			logger(LOG_ERR, "Cannot join multicast group %s %s: %s", host, port, sockstrerror(sockerrno));
			closesocket(device_fd);
			free(host);
			return false;
		}

#ifdef IPV6_MULTICAST_LOOP
		setsockopt(device_fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (const void *)&one, sizeof(one));
#endif
#ifdef IPV6_MULTICAST_HOPS
		setsockopt(device_fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (void *)&ttl, sizeof(ttl));
#endif
	}
	break;
#endif

	default:
		logger(LOG_ERR, "Multicast for address family %x unsupported", ai->ai_family);
		closesocket(device_fd);
		free(host);
		return false;
	}

	free(host);
	logger(LOG_INFO, "%s is a %s", device, device_info);

	return true;
}

static void close_device(void) {
	close(device_fd);

	free(device);
	free(iface);

	if(ai) {
		freeaddrinfo(ai);
	}
}

static bool read_packet(vpn_packet_t *packet) {
	int lenin;

	if((lenin = recv(device_fd, (void *)packet->data, MTU, 0)) <= 0) {
		logger(LOG_ERR, "Error while reading from %s %s: %s", device_info,
		       device, strerror(errno));
		return false;
	}

	if(!memcmp(&ignore_src, packet->data + 6, sizeof(ignore_src))) {
		ifdebug(SCARY_THINGS) logger(LOG_DEBUG, "Ignoring loopback packet of %d bytes from %s", lenin, device_info);
		packet->len = 0;
		return true;
	}

	packet->len = lenin;

	device_total_in += packet->len;

	ifdebug(TRAFFIC) logger(LOG_DEBUG, "Read packet of %d bytes from %s", packet->len,
	                        device_info);

	return true;
}

static bool write_packet(vpn_packet_t *packet) {
	ifdebug(TRAFFIC) logger(LOG_DEBUG, "Writing packet of %d bytes to %s",
	                        packet->len, device_info);

	if(sendto(device_fd, (void *)packet->data, packet->len, 0, ai->ai_addr, ai->ai_addrlen) < 0) {
		logger(LOG_ERR, "Can't write to %s %s: %s", device_info, device,
		       strerror(errno));
		return false;
	}

	device_total_out += packet->len;

	memcpy(&ignore_src, packet->data + 6, sizeof(ignore_src));

	return true;
}

static void dump_device_stats(void) {
	logger(LOG_DEBUG, "Statistics for %s %s:", device_info, device);
	logger(LOG_DEBUG, " total bytes in:  %10"PRIu64, device_total_in);
	logger(LOG_DEBUG, " total bytes out: %10"PRIu64, device_total_out);
}

const devops_t multicast_devops = {
	.setup = setup_device,
	.close = close_device,
	.read = read_packet,
	.write = write_packet,
	.dump_stats = dump_device_stats,
};

#if 0

static bool not_supported(void) {
	logger(LOG_ERR, "Raw socket device not supported on this platform");
	return false;
}

const devops_t multicast_devops = {
	.setup = not_supported,
	.close = NULL,
	.read = NULL,
	.write = NULL,
	.dump_stats = NULL,
};
#endif
