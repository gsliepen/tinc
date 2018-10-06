/*
    device.c -- Dummy device
    Copyright (C) 2011-2012 Guus Sliepen <guus@tinc-vpn.org>

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

#include "device.h"
#include "logger.h"
#include "net.h"
#include "xalloc.h"

static const char *device_info = "dummy device";

static bool setup_device(void) {
	device = xstrdup("dummy");
	iface = xstrdup("dummy");
	logger(DEBUG_ALWAYS, LOG_INFO, "%s (%s) is a %s", device, iface, device_info);
	return true;
}

static void close_device(void) {
}

static bool read_packet(vpn_packet_t *packet) {
	(void)packet;
	return false;
}

static bool write_packet(vpn_packet_t *packet) {
	(void)packet;
	return true;
}

const devops_t dummy_devops = {
	.setup = setup_device,
	.close = close_device,
	.read = read_packet,
	.write = write_packet,
};
