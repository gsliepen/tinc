/*
    device.c -- VDE plug
    Copyright (C) 2013 Guus Sliepen <guus@tinc-vpn.org>

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

#include <libvdeplug.h>

#include "conf.h"
#include "device.h"
#include "names.h"
#include "net.h"
#include "logger.h"
#include "route.h"
#include "xalloc.h"

static struct vdeconn *conn = NULL;
static int port = 0;
static char *group = NULL;
static const char *device_info = "VDE socket";

static bool setup_device(void) {
	if(!get_config_string(lookup_config(&config_tree, "Device"), &device)) {
		xasprintf(&device, RUNSTATEDIR "/vde.ctl");
	}

	get_config_string(lookup_config(&config_tree, "Interface"), &iface);

	get_config_int(lookup_config(&config_tree, "VDEPort"), &port);

	get_config_string(lookup_config(&config_tree, "VDEGroup"), &group);

	struct vde_open_args args = {
		.port = port,
		.group = group,
		.mode = 0700,
	};

	conn = vde_open(device, identname, &args);

	if(!conn) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open VDE socket %s", device);
		return false;
	}

	device_fd = vde_datafd(conn);

#ifdef FD_CLOEXEC
	fcntl(device_fd, F_SETFD, FD_CLOEXEC);
#endif

	logger(DEBUG_ALWAYS, LOG_INFO, "%s is a %s", device, device_info);

	if(routing_mode == RMODE_ROUTER) {
		overwrite_mac = true;
	}

	return true;
}

static void close_device(void) {
	if(conn) {
		vde_close(conn);
		conn = NULL;
	}

	free(device);
	device = NULL;

	free(iface);
	iface = NULL;

	device_info = NULL;
}

static bool read_packet(vpn_packet_t *packet) {
	ssize_t lenin = vde_recv(conn, DATA(packet), MTU, 0);

	if(lenin <= 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while reading from %s %s: %s", device_info, device, strerror(errno));
		event_exit();
		return false;
	}

	if(lenin == 1) {
		logger(DEBUG_TRAFFIC, LOG_DEBUG,
		       "Dropped a packet received from %s - the sender was not allowed to send that packet.", device_info);
		return false;
	}

	if(lenin < 14) {
		logger(DEBUG_TRAFFIC, LOG_DEBUG,
		       "Received an invalid packet from %s - packet shorter than an ethernet header).", device_info);
		return false;
	}

	packet->len = lenin;

	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Read packet of %d bytes from %s", packet->len, device_info);

	return true;
}

static bool write_packet(vpn_packet_t *packet) {
	if(vde_send(conn, DATA(packet), packet->len, 0) < 0) {
		if(errno != EINTR && errno != EAGAIN) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Can't write to %s %s: %s", device_info, device, strerror(errno));
			event_exit();
		}

		return false;
	}

	return true;
}

const devops_t vde_devops = {
	.setup = setup_device,
	.close = close_device,
	.read = read_packet,
	.write = write_packet,
};
