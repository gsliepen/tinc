/*
    device.c -- multicast socket
    Copyright (C) 2002-2005 Ivo Timmermans,
                  2002-2013 Guus Sliepen <guus@tinc-vpn.org>

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
#include "xalloc.h"

static const char *device_info = "multicast socket";

static struct addrinfo *ai = NULL;
static mac_t ignore_src = {0};

static bool setup_device(void) {
	char *host = NULL;
	char *port;
	char *space;
	int ttl = 1;

	get_config_string(lookup_config(&config_tree, "Interface"), &iface);

	if(!get_config_string(lookup_config(&config_tree, "Device"), &device)) {
		logger(DEBUG_ALWAYS, LOG_ERR, _("Device variable required for %s"), device_info);
		goto error;
	}

	host = xstrdup(device);
	space = strchr(host, ' ');

	if(!space) {
		logger(DEBUG_ALWAYS, LOG_ERR, _("Port number required for %s"), device_info);
		goto error;
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
		goto error;
	}

	device_fd = socket(ai->ai_family, SOCK_DGRAM, IPPROTO_UDP);

	if(device_fd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, _("Creating socket failed: %s"), sockstrerror(sockerrno));
		goto error;
	}

#ifdef FD_CLOEXEC
	fcntl(device_fd, F_SETFD, FD_CLOEXEC);
#endif

	static const int one = 1;
	setsockopt(device_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof(one));

	if(bind(device_fd, ai->ai_addr, ai->ai_addrlen)) {
		logger(DEBUG_ALWAYS, LOG_ERR, _("Can't bind to %s %s: %s"), host, port, sockstrerror(sockerrno));
		goto error;
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
			logger(DEBUG_ALWAYS, LOG_ERR, _("Cannot join multicast group %s %s: %s"), host, port, sockstrerror(sockerrno));
			goto error;
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
			logger(DEBUG_ALWAYS, LOG_ERR, _("Cannot join multicast group %s %s: %s"), host, port, sockstrerror(sockerrno));
			goto error;
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
		logger(DEBUG_ALWAYS, LOG_ERR, _("Multicast for address family %x unsupported"), ai->ai_family);
		goto error;
	}

	logger(DEBUG_ALWAYS, LOG_INFO, _("%s is a %s"), device, device_info);

	return true;

error:

	if(device_fd >= 0) {
		closesocket(device_fd);
	}

	if(ai) {
		freeaddrinfo(ai);
	}

	free(host);

	return false;
}

static void close_device(void) {
	close(device_fd);
	device_fd = -1;

	free(device);
	device = NULL;
	free(iface);
	iface = NULL;

	if(ai) {
		freeaddrinfo(ai);
		ai = NULL;
	}

	device_info = NULL;
}

static bool read_packet(vpn_packet_t *packet) {
	ssize_t lenin;

	if((lenin = recv(device_fd, (void *)DATA(packet), MTU, 0)) <= 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, _("Error while reading from %s %s: %s"), device_info,
		       device, sockstrerror(sockerrno));
		return false;
	}

	if(!memcmp(&ignore_src, DATA(packet) + 6, sizeof(ignore_src))) {
		logger(DEBUG_SCARY_THINGS, LOG_DEBUG, _("Ignoring loopback packet of %zd bytes from %s"), lenin, device_info);
		return false;
	}

	packet->len = lenin;

	logger(DEBUG_TRAFFIC, LOG_DEBUG, _("Read packet of %d bytes from %s"), packet->len,
	       device_info);

	return true;
}

static bool write_packet(vpn_packet_t *packet) {
	logger(DEBUG_TRAFFIC, LOG_DEBUG, _("Writing packet of %d bytes to %s"),
	       packet->len, device_info);

	if(sendto(device_fd, (void *)DATA(packet), packet->len, 0, ai->ai_addr, ai->ai_addrlen) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, _("Can't write to %s %s: %s"), device_info, device,
		       sockstrerror(sockerrno));
		return false;
	}

	memcpy(&ignore_src, DATA(packet) + 6, sizeof(ignore_src));

	return true;
}

const devops_t multicast_devops = {
	.setup = setup_device,
	.close = close_device,
	.read = read_packet,
	.write = write_packet,
};
