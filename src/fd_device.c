/*
    fd_device.c -- Interaction with Android tun fd
    Copyright (C)   2001-2005   Ivo Timmermans,
                    2001-2016   Guus Sliepen <guus@tinc-vpn.org>
                    2009        Grzegorz Dymarek <gregd72002@googlemail.com>
                    2016        Pacien TRAN-GIRARD <pacien@pacien.net>

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
#include "ethernet.h"
#include "logger.h"
#include "net.h"
#include "route.h"
#include "utils.h"

static inline bool check_config(void) {
	if(routing_mode == RMODE_SWITCH) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Switch mode not supported (requires unsupported TAP device)!");
		return false;
	}

	if(!get_config_int(lookup_config(config_tree, "Device"), &device_fd)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not read fd from configuration!");
		return false;
	}

	return true;
}

static bool setup_device(void) {
	if(!check_config()) {
		return false;
	}

	if(device_fd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open %s: %s!", device, strerror(errno));
		return false;
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "fd/%d adapter set up.", device_fd);

	return true;
}

static void close_device(void) {
	close(device_fd);
	device_fd = -1;
}

static inline uint16_t get_ip_ethertype(vpn_packet_t *packet) {
	switch(DATA(packet)[ETH_HLEN] >> 4) {
	case 4:
		return ETH_P_IP;

	case 6:
		return ETH_P_IPV6;

	default:
		return ETH_P_MAX;
	}
}

static inline void set_etherheader(vpn_packet_t *packet, uint16_t ethertype) {
	memset(DATA(packet), 0, ETH_HLEN - ETHER_TYPE_LEN);

	DATA(packet)[ETH_HLEN - ETHER_TYPE_LEN] = (ethertype >> 8) & 0xFF;
	DATA(packet)[ETH_HLEN - ETHER_TYPE_LEN + 1] = ethertype & 0xFF;
}

static bool read_packet(vpn_packet_t *packet) {
	int lenin = read(device_fd, DATA(packet) + ETH_HLEN, MTU - ETH_HLEN);

	if(lenin <= 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while reading from fd/%d: %s!", device_fd, strerror(errno));
		return false;
	}

	uint16_t ethertype = get_ip_ethertype(packet);

	if(ethertype == ETH_P_MAX) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "Unknown IP version while reading packet from fd/%d!", device_fd);
		return false;
	}

	set_etherheader(packet, ethertype);
	packet->len = lenin + ETH_HLEN;

	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Read packet of %d bytes from fd/%d.", packet->len, device_fd);

	return true;
}

static bool write_packet(vpn_packet_t *packet) {
	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Writing packet of %d bytes to fd/%d.", packet->len, device_fd);

	if(write(device_fd, DATA(packet) + ETH_HLEN, packet->len - ETH_HLEN) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while writing to fd/%d: %s!", device_fd, strerror(errno));
		return false;
	}

	return true;
}

const devops_t fd_devops = {
	.setup = setup_device,
	.close = close_device,
	.read = read_packet,
	.write = write_packet,
};
