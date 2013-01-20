/*
    device.c -- Interaction with Linux ethertap and tun/tap device
    Copyright (C) 2001-2005 Ivo Timmermans,
                  2001-2013 Guus Sliepen <guus@tinc-vpn.org>

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
#include "names.h"
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
static char *type = NULL;
static char ifrname[IFNAMSIZ];
static char *device_info;

uint64_t device_in_packets = 0;
uint64_t device_in_bytes = 0;
uint64_t device_out_packets = 0;
uint64_t device_out_bytes = 0;

static bool setup_device(void) {
	if(!get_config_string(lookup_config(config_tree, "Device"), &device))
		device = xstrdup(DEFAULT_DEVICE);

	if(!get_config_string(lookup_config(config_tree, "Interface"), &iface))
		if(netname)
			iface = xstrdup(netname);

	device_fd = open(device, O_RDWR | O_NONBLOCK);

	if(device_fd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open %s: %s", device, strerror(errno));
		return false;
	}

#ifdef FD_CLOEXEC
	fcntl(device_fd, F_SETFD, FD_CLOEXEC);
#endif

	struct ifreq ifr = {{{0}}};

	get_config_string(lookup_config(config_tree, "DeviceType"), &type);

	if(type && strcasecmp(type, "tun") && strcasecmp(type, "tap")) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unknown device type %s!", type);
		return false;
	}

	if((type && !strcasecmp(type, "tun")) || (!type && routing_mode == RMODE_ROUTER)) {
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
		free(iface);
		iface = xstrdup(ifrname);
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "%s is a %s", device, device_info);

	return true;
}

static void close_device(void) {
	close(device_fd);

	free(type);
	free(device);
	free(iface);
}

static bool read_packet(vpn_packet_t *packet) {
	int inlen;

	switch(device_type) {
		case DEVICE_TYPE_TUN:
			inlen = read(device_fd, packet->data + 10, MTU - 10);

			if(inlen <= 0) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Error while reading from %s %s: %s",
					   device_info, device, strerror(errno));
				return false;
			}

			memset(packet->data, 0, 12);
			packet->len = inlen + 10;
			break;
		case DEVICE_TYPE_TAP:
			inlen = read(device_fd, packet->data, MTU);

			if(inlen <= 0) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Error while reading from %s %s: %s",
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

	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Read packet of %d bytes from %s", packet->len,
			   device_info);

	return true;
}

static bool write_packet(vpn_packet_t *packet) {
	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Writing packet of %d bytes to %s",
			   packet->len, device_info);

	switch(device_type) {
		case DEVICE_TYPE_TUN:
			packet->data[10] = packet->data[11] = 0;
			if(write(device_fd, packet->data + 10, packet->len - 10) < 0) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Can't write to %s %s: %s", device_info, device,
					   strerror(errno));
				return false;
			}
			break;
		case DEVICE_TYPE_TAP:
			if(write(device_fd, packet->data, packet->len) < 0) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Can't write to %s %s: %s", device_info, device,
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

static void dump_device_stats(void) {
	logger(DEBUG_ALWAYS, LOG_DEBUG, "Statistics for %s %s:", device_info, device);
	logger(DEBUG_ALWAYS, LOG_DEBUG, " total bytes in:  %10"PRIu64, device_in_bytes);
	logger(DEBUG_ALWAYS, LOG_DEBUG, " total bytes out: %10"PRIu64, device_out_bytes);
}

const devops_t os_devops = {
	.setup = setup_device,
	.close = close_device,
	.read = read_packet,
	.write = write_packet,
	.dump_stats = dump_device_stats,
};
