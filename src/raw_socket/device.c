/*
    device.c -- raw socket
    Copyright (C) 2002-2005 Ivo Timmermans,
                  2002-2009 Guus Sliepen <guus@tinc-vpn.org>

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

#include <netpacket/packet.h>

#include "conf.h"
#include "device.h"
#include "net.h"
#include "logger.h"
#include "utils.h"
#include "route.h"
#include "xalloc.h"

int device_fd = -1;
char *device = NULL;
char *iface = NULL;
static char ifrname[IFNAMSIZ];
static char *device_info;

static uint64_t device_total_in = 0;
static uint64_t device_total_out = 0;

bool setup_device(void) {
	struct ifreq ifr;
	struct sockaddr_ll sa;

	if(!get_config_string(lookup_config(config_tree, "Interface"), &iface))
		iface = xstrdup("eth0");

	if(!get_config_string(lookup_config(config_tree, "Device"), &device))
		device = xstrdup(iface);

	device_info = "raw socket";

	if((device_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		logger(LOG_ERR, "Could not open %s: %s", device_info,
			   strerror(errno));
		return false;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_ifrn.ifrn_name, iface, IFNAMSIZ);
	if(ioctl(device_fd, SIOCGIFINDEX, &ifr)) {
		close(device_fd);
		logger(LOG_ERR, "Can't find interface %s: %s", iface,
			   strerror(errno));
		return false;
	}

	memset(&sa, '0', sizeof(sa));
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_ALL);
	sa.sll_ifindex = ifr.ifr_ifindex;

	if(bind(device_fd, (struct sockaddr *) &sa, (socklen_t) sizeof(sa))) {
		logger(LOG_ERR, "Could not bind %s to %s: %s", device, iface, strerror(errno));
		return false;
	}

	logger(LOG_INFO, "%s is a %s", device, device_info);

	return true;
}

void close_device(void) {
	close(device_fd);

	free(device);
	free(iface);
}

bool read_packet(vpn_packet_t *packet) {
	int lenin;

	if((lenin = read(device_fd, packet->data, MTU)) <= 0) {
		logger(LOG_ERR, "Error while reading from %s %s: %s", device_info,
			   device, strerror(errno));
		return false;
	}

	packet->len = lenin;

	device_total_in += packet->len;

	ifdebug(TRAFFIC) logger(LOG_DEBUG, "Read packet of %d bytes from %s", packet->len,
			   device_info);

	return true;
}

bool write_packet(vpn_packet_t *packet) {
	ifdebug(TRAFFIC) logger(LOG_DEBUG, "Writing packet of %d bytes to %s",
			   packet->len, device_info);

	if(write(device_fd, packet->data, packet->len) < 0) {
		logger(LOG_ERR, "Can't write to %s %s: %s", device_info, device,
			   strerror(errno));
		return false;
	}

	device_total_out += packet->len;

	return true;
}

void dump_device_stats(void) {
	logger(LOG_DEBUG, "Statistics for %s %s:", device_info, device);
	logger(LOG_DEBUG, " total bytes in:  %10"PRIu64, device_total_in);
	logger(LOG_DEBUG, " total bytes out: %10"PRIu64, device_total_out);
}
