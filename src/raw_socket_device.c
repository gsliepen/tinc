/*
    device.c -- raw socket
    Copyright (C) 2002-2005 Ivo Timmermans,
                  2002-2012 Guus Sliepen <guus@tinc-vpn.org>

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

#ifdef HAVE_NETPACKET_PACKET_H
#include <netpacket/packet.h>
#endif

#include "conf.h"
#include "device.h"
#include "net.h"
#include "logger.h"
#include "utils.h"
#include "route.h"
#include "xalloc.h"

#if defined(PF_PACKET) && defined(ETH_P_ALL) && defined(AF_PACKET) && defined(SIOCGIFINDEX)
static char *device_info;

static bool setup_device(void) {
	struct ifreq ifr;
	struct sockaddr_ll sa;

	if(!get_config_string(lookup_config(config_tree, "Interface"), &iface))
		iface = xstrdup("eth0");

	if(!get_config_string(lookup_config(config_tree, "Device"), &device))
		device = xstrdup(iface);

	device_info = "raw socket";

	if((device_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open %s: %s", device_info,
			   strerror(errno));
		return false;
	}

	memset(&ifr, 0, sizeof ifr);

#ifdef FD_CLOEXEC
	fcntl(device_fd, F_SETFD, FD_CLOEXEC);
#endif

	strncpy(ifr.ifr_ifrn.ifrn_name, iface, IFNAMSIZ);
	if(ioctl(device_fd, SIOCGIFINDEX, &ifr)) {
		close(device_fd);
		logger(DEBUG_ALWAYS, LOG_ERR, "Can't find interface %s: %s", iface,
			   strerror(errno));
		return false;
	}

	memset(&sa, '0', sizeof sa);
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_ALL);
	sa.sll_ifindex = ifr.ifr_ifindex;

	if(bind(device_fd, (struct sockaddr *) &sa, (socklen_t) sizeof sa)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not bind %s to %s: %s", device, iface, strerror(errno));
		return false;
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "%s is a %s", device, device_info);

	return true;
}

static void close_device(void) {
	close(device_fd); device_fd = -1;

	free(device); device = NULL;
	free(iface); iface = NULL;
	device_info = NULL;
}

static bool read_packet(vpn_packet_t *packet) {
	int inlen;

	if((inlen = read(device_fd, DATA(packet), MTU)) <= 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while reading from %s %s: %s", device_info,
			   device, strerror(errno));
		return false;
	}

	packet->len = inlen;

	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Read packet of %d bytes from %s", packet->len,
			   device_info);

	return true;
}

static bool write_packet(vpn_packet_t *packet) {
	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Writing packet of %d bytes to %s",
			   packet->len, device_info);

	if(write(device_fd, DATA(packet), packet->len) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Can't write to %s %s: %s", device_info, device,
			   strerror(errno));
		return false;
	}

	return true;
}

const devops_t raw_socket_devops = {
	.setup = setup_device,
	.close = close_device,
	.read = read_packet,
	.write = write_packet,
};

#else

static bool not_supported(void) {
	logger(DEBUG_ALWAYS, LOG_ERR, "Raw socket device not supported on this platform");
	return false;
}

const devops_t raw_socket_devops = {
	.setup = not_supported,
	.close = NULL,
	.read = NULL,
	.write = NULL,
};
#endif
