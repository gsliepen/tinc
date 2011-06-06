/*
    device.c -- Interaction with Linux ethertap and tun/tap device
    Copyright (C) 2001-2005 Ivo Timmermans,
                  2001-2009 Guus Sliepen <guus@tinc-vpn.org>

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

#include <linux/if_tun.h>
#define DEFAULT_DEVICE "/dev/net/tun"

#include "conf.h"
#include "device.h"
#include "logger.h"
#include "net.h"
#include "route.h"
#include "utils.h"
#include "xalloc.h"
#include "device.h"

typedef enum device_type_t {
	DEVICE_TYPE_TUN,
	DEVICE_TYPE_TAP,
} device_type_t;

int device_fd = -1;
static device_type_t device_type;
char *device = NULL;
char *iface = NULL;
static char ifrname[IFNAMSIZ];
static char *device_info;

uint64_t device_in_packets = 0;
uint64_t device_in_bytes = 0;
uint64_t device_out_packets = 0;
uint64_t device_out_bytes = 0;

bool setup_device(void) {
	if(!get_config_string(lookup_config(config_tree, "Device"), &device))
		device = xstrdup(DEFAULT_DEVICE);

	if(!get_config_string(lookup_config(config_tree, "Interface"), &iface))
#ifdef HAVE_LINUX_IF_TUN_H
		if (netname != NULL)
			iface = xstrdup(netname);
#else
		iface = xstrdup(strrchr(device, '/') ? strrchr(device, '/') + 1 : device);
#endif
	device_fd = open(device, O_RDWR | O_NONBLOCK);

	if(device_fd < 0) {
		logger(LOG_ERR, "Could not open %s: %s", device, strerror(errno));
		return false;
	}

	struct ifreq ifr = {{{0}}};

	if(routing_mode == RMODE_ROUTER) {
		ifr.ifr_flags = IFF_TUN;
		device_type = DEVICE_TYPE_TUN;
		device_info = "Linux tun/tap device (tun mode)";
	} else {
		ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
		device_type = DEVICE_TYPE_TAP;
		device_info = "Linux tun/tap device (tap mode)";
	}

#ifdef IFF_ONE_QUEUE
	/* Set IFF_ONE_QUEUE flag... */

	bool t1q = false;
	if(get_config_bool(lookup_config(config_tree, "IffOneQueue"), &t1q) && t1q)
		ifr.ifr_flags |= IFF_ONE_QUEUE;
#endif

	if(iface)
		strncpy(ifr.ifr_name, iface, IFNAMSIZ);

	if(!ioctl(device_fd, TUNSETIFF, &ifr)) {
		strncpy(ifrname, ifr.ifr_name, IFNAMSIZ);
		if(iface) free(iface);
		iface = xstrdup(ifrname);
	} else if(!ioctl(device_fd, (('T' << 8) | 202), &ifr)) {
		logger(LOG_WARNING, "Old ioctl() request was needed for %s", device);
		strncpy(ifrname, ifr.ifr_name, IFNAMSIZ);
		if(iface) free(iface);
		iface = xstrdup(ifrname);
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
	int inlen;
	
	switch(device_type) {
		case DEVICE_TYPE_TUN:
			inlen = read(device_fd, packet->data + 10, MTU - 10);

			if(inlen <= 0) {
				logger(LOG_ERR, "Error while reading from %s %s: %s",
					   device_info, device, strerror(errno));
				return false;
			}

			packet->len = inlen + 10;
			break;
		case DEVICE_TYPE_TAP:
			inlen = read(device_fd, packet->data, MTU);

			if(inlen <= 0) {
				logger(LOG_ERR, "Error while reading from %s %s: %s",
					   device_info, device, strerror(errno));
				return false;
			}

			packet->len = inlen;
			break;
		default:
			abort();
	}

	device_in_packets++;
	device_in_bytes += packet->len;

	ifdebug(TRAFFIC) logger(LOG_DEBUG, "Read packet of %d bytes from %s", packet->len,
			   device_info);

	return true;
}

bool write_packet(vpn_packet_t *packet) {
	ifdebug(TRAFFIC) logger(LOG_DEBUG, "Writing packet of %d bytes to %s",
			   packet->len, device_info);

	switch(device_type) {
		case DEVICE_TYPE_TUN:
			packet->data[10] = packet->data[11] = 0;
			if(write(device_fd, packet->data + 10, packet->len - 10) < 0) {
				logger(LOG_ERR, "Can't write to %s %s: %s", device_info, device,
					   strerror(errno));
				return false;
			}
			break;
		case DEVICE_TYPE_TAP:
			if(write(device_fd, packet->data, packet->len) < 0) {
				logger(LOG_ERR, "Can't write to %s %s: %s", device_info, device,
					   strerror(errno));
				return false;
			}
			break;
		default:
			abort();
	}

	device_out_packets++;
	device_out_bytes += packet->len;

	return true;
}

void dump_device_stats(void) {
	logger(LOG_DEBUG, "Statistics for %s %s:", device_info, device);
	logger(LOG_DEBUG, " total bytes in:  %10"PRIu64, device_in_bytes);
	logger(LOG_DEBUG, " total bytes out: %10"PRIu64, device_out_bytes);
}
