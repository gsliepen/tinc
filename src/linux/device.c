/*
    device.c -- Interaction with Linux ethertap and tun/tap device
    Copyright (C) 2001-2005 Ivo Timmermans,
                  2001-2006 Guus Sliepen <guus@tinc-vpn.org>

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

    $Id$
*/

#include "system.h"

#ifdef HAVE_LINUX_IF_TUN_H
#include <linux/if_tun.h>
#define DEFAULT_DEVICE "/dev/net/tun"
#else
#define DEFAULT_DEVICE "/dev/tap0"
#endif

#include "conf.h"
#include "logger.h"
#include "net.h"
#include "route.h"
#include "utils.h"

typedef enum device_type_t {
	DEVICE_TYPE_ETHERTAP,
	DEVICE_TYPE_TUN,
	DEVICE_TYPE_TAP,
} device_type_t;

int device_fd = -1;
static device_type_t device_type;
char *device;
char *iface;
char ifrname[IFNAMSIZ];
char *device_info;

static int device_total_in = 0;
static int device_total_out = 0;

bool setup_device(void) {
	struct ifreq ifr;

	cp();

	if(!get_config_string(lookup_config(config_tree, "Device"), &device))
		device = DEFAULT_DEVICE;

	if(!get_config_string(lookup_config(config_tree, "Interface"), &iface))
#ifdef HAVE_LINUX_IF_TUN_H
		iface = netname;
#else
		iface = rindex(device, '/') ? rindex(device, '/') + 1 : device;
#endif
	device_fd = open(device, O_RDWR | O_NONBLOCK);

	if(device_fd < 0) {
		logger(LOG_ERR, _("Could not open %s: %s"), device, strerror(errno));
		return false;
	}

#ifdef HAVE_LINUX_IF_TUN_H
	/* Ok now check if this is an old ethertap or a new tun/tap thingie */

	memset(&ifr, 0, sizeof ifr);
	if(routing_mode == RMODE_ROUTER) {
		ifr.ifr_flags = IFF_TUN;
		device_type = DEVICE_TYPE_TUN;
		device_info = _("Linux tun/tap device (tun mode)");
	} else {
		ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
		device_type = DEVICE_TYPE_TAP;
		device_info = _("Linux tun/tap device (tap mode)");
	}

	if(iface)
		strncpy(ifr.ifr_name, iface, IFNAMSIZ);

	if(!ioctl(device_fd, TUNSETIFF, &ifr)) {
		strncpy(ifrname, ifr.ifr_name, IFNAMSIZ);
		iface = ifrname;
	} else if(!ioctl(device_fd, (('T' << 8) | 202), &ifr)) {
		logger(LOG_WARNING, _("Old ioctl() request was needed for %s"), device);
		strncpy(ifrname, ifr.ifr_name, IFNAMSIZ);
		iface = ifrname;
	} else
#endif
	{
		if(routing_mode == RMODE_ROUTER)
			overwrite_mac = true;
		device_info = _("Linux ethertap device");
		device_type = DEVICE_TYPE_ETHERTAP;
		iface = rindex(device, '/') ? rindex(device, '/') + 1 : device;
	}

	logger(LOG_INFO, _("%s is a %s"), device, device_info);

	return true;
}

void close_device(void) {
	cp();
	
	close(device_fd);
}

bool read_packet(vpn_packet_t *packet) {
	int inlen;
	
	cp();

	switch(device_type) {
		case DEVICE_TYPE_TUN:
			inlen = read(device_fd, packet->data + 10, MTU - 10);

			if(inlen <= 0) {
				logger(LOG_ERR, _("Error while reading from %s %s: %s"),
					   device_info, device, strerror(errno));
				return false;
			}

			packet->len = inlen + 10;
			break;
		case DEVICE_TYPE_TAP:
			inlen = read(device_fd, packet->data, MTU);

			if(inlen <= 0) {
				logger(LOG_ERR, _("Error while reading from %s %s: %s"),
					   device_info, device, strerror(errno));
				return false;
			}

			packet->len = inlen;
			break;
		case DEVICE_TYPE_ETHERTAP:
			inlen = read(device_fd, packet->data - 2, MTU + 2);

			if(inlen <= 0) {
				logger(LOG_ERR, _("Error while reading from %s %s: %s"),
					   device_info, device, strerror(errno));
				return false;
			}

			packet->len = inlen - 2;
			break;
	}

	device_total_in += packet->len;

	ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Read packet of %d bytes from %s"), packet->len,
			   device_info);

	return true;
}

bool write_packet(vpn_packet_t *packet) {
	cp();

	ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Writing packet of %d bytes to %s"),
			   packet->len, device_info);

	switch(device_type) {
		case DEVICE_TYPE_TUN:
			packet->data[10] = packet->data[11] = 0;
			if(write(device_fd, packet->data + 10, packet->len - 10) < 0) {
				logger(LOG_ERR, _("Can't write to %s %s: %s"), device_info, device,
					   strerror(errno));
				return false;
			}
			break;
		case DEVICE_TYPE_TAP:
			if(write(device_fd, packet->data, packet->len) < 0) {
				logger(LOG_ERR, _("Can't write to %s %s: %s"), device_info, device,
					   strerror(errno));
				return false;
			}
			break;
		case DEVICE_TYPE_ETHERTAP:
			*(short int *)(packet->data - 2) = packet->len;

			if(write(device_fd, packet->data - 2, packet->len + 2) < 0) {
				logger(LOG_ERR, _("Can't write to %s %s: %s"), device_info, device,
					   strerror(errno));
				return false;
			}
			break;
	}

	device_total_out += packet->len;

	return true;
}

void dump_device_stats(void) {
	cp();

	logger(LOG_DEBUG, _("Statistics for %s %s:"), device_info, device);
	logger(LOG_DEBUG, _(" total bytes in:  %10d"), device_total_in);
	logger(LOG_DEBUG, _(" total bytes out: %10d"), device_total_out);
}
