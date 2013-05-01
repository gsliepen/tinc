/*
    device.c -- Interaction with Solaris tun device
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


#include "../system.h"

#include <sys/stropts.h>
#include <sys/sockio.h>
#include <net/if_tun.h>

#include "../conf.h"
#include "../device.h"
#include "../logger.h"
#include "../names.h"
#include "../net.h"
#include "../utils.h"
#include "../xalloc.h"

#define DEFAULT_DEVICE "/dev/tun"

int device_fd = -1;
static int ip_fd = -1, if_fd = -1;
char *device = NULL;
char *iface = NULL;
static char *device_info = NULL;

static uint64_t device_total_in = 0;
static uint64_t device_total_out = 0;

static bool setup_device(void) {
	int ppa;
	char *ptr;

	if(!get_config_string(lookup_config(config_tree, "Device"), &device))
		device = xstrdup(DEFAULT_DEVICE);

	if((device_fd = open(device, O_RDWR | O_NONBLOCK)) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open %s: %s", device, strerror(errno));
		return false;
	}

#ifdef FD_CLOEXEC
	fcntl(device_fd, F_SETFD, FD_CLOEXEC);
#endif

	ppa = 0;

	ptr = device;
	while(*ptr && !isdigit((int) *ptr))
		ptr++;
	ppa = atoi(ptr);

	if((ip_fd = open("/dev/ip", O_RDWR, 0)) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open /dev/ip: %s", strerror(errno));
		return false;
	}

#ifdef FD_CLOEXEC
	fcntl(ip_fd, F_SETFD, FD_CLOEXEC);
#endif

	/* Assign a new PPA and get its unit number. */
	if((ppa = ioctl(device_fd, TUNNEWPPA, ppa)) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Can't assign new interface: %s", strerror(errno));
		return false;
	}

	if((if_fd = open(device, O_RDWR, 0)) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open %s twice: %s", device,
			   strerror(errno));
		return false;
	}

#ifdef FD_CLOEXEC
	fcntl(if_fd, F_SETFD, FD_CLOEXEC);
#endif

	if(ioctl(if_fd, I_PUSH, "ip") < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Can't push IP module: %s", strerror(errno));
		return false;
	}

	/* Assign ppa according to the unit number returned by tun device */
	if(ioctl(if_fd, IF_UNITSEL, (char *) &ppa) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Can't set PPA %d: %s", ppa, strerror(errno));
		return false;
	}

	if(ioctl(ip_fd, I_LINK, if_fd) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Can't link TUN device to IP: %s", strerror(errno));
		return false;
	}

	if(!get_config_string(lookup_config(config_tree, "Interface"), &iface))
		xasprintf(&iface, "tun%d", ppa);

	device_info = "Solaris tun device";

	logger(DEBUG_ALWAYS, LOG_INFO, "%s is a %s", device, device_info);

	return true;
}

static void close_device(void) {
	close(if_fd);
	close(ip_fd);
	close(device_fd);

	free(device);
	free(iface);
}

static bool read_packet(vpn_packet_t *packet) {
	int inlen;

	if((inlen = read(device_fd, packet->data + 14, MTU - 14)) <= 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while reading from %s %s: %s", device_info,
			   device, strerror(errno));
		return false;
	}

	switch(packet->data[14] >> 4) {
		case 4:
			packet->data[12] = 0x08;
			packet->data[13] = 0x00;
			break;
		case 6:
			packet->data[12] = 0x86;
			packet->data[13] = 0xDD;
			break;
		default:
			logger(DEBUG_TRAFFIC, LOG_ERR,
					   "Unknown IP version %d while reading packet from %s %s",
					   packet->data[14] >> 4, device_info, device);
			return false;
	}

	memset(packet->data, 0, 12);
	packet->len = inlen + 14;

	device_total_in += packet->len;

	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Read packet of %d bytes from %s", packet->len,
			   device_info);

	return true;
}

static bool write_packet(vpn_packet_t *packet) {
	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Writing packet of %d bytes to %s",
			   packet->len, device_info);

	if(write(device_fd, packet->data + 14, packet->len - 14) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Can't write to %s %s: %s", device_info,
			   device, strerror(errno));
		return false;
	}

	device_total_out += packet->len;

	return true;
}

static void dump_device_stats(void) {
	logger(DEBUG_ALWAYS, LOG_DEBUG, "Statistics for %s %s:", device_info, device);
	logger(DEBUG_ALWAYS, LOG_DEBUG, " total bytes in:  %10"PRIu64, device_total_in);
	logger(DEBUG_ALWAYS, LOG_DEBUG, " total bytes out: %10"PRIu64, device_total_out);
}

const devops_t os_devops = {
	.setup = setup_device,
	.close = close_device,
	.read = read_packet,
	.write = write_packet,
	.dump_stats = dump_device_stats,
};
