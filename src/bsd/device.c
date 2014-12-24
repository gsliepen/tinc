/*
    device.c -- Interaction BSD tun/tap device
    Copyright (C) 2001-2005 Ivo Timmermans,
                  2001-2014 Guus Sliepen <guus@tinc-vpn.org>
                  2009      Grzegorz Dymarek <gregd72002@googlemail.com>

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

#include "../conf.h"
#include "../device.h"
#include "../logger.h"
#include "../names.h"
#include "../net.h"
#include "../route.h"
#include "../utils.h"
#include "../xalloc.h"

#ifdef ENABLE_TUNEMU
#include "bsd/tunemu.h"
#endif

#define DEFAULT_TUN_DEVICE "/dev/tun0"
#if defined(HAVE_DARWIN) || defined(HAVE_FREEBSD) || defined(HAVE_NETBSD)
#define DEFAULT_TAP_DEVICE "/dev/tap0"
#else
#define DEFAULT_TAP_DEVICE "/dev/tun0"
#endif

typedef enum device_type {
	DEVICE_TYPE_TUN,
	DEVICE_TYPE_TUNIFHEAD,
	DEVICE_TYPE_TAP,
#ifdef ENABLE_TUNEMU
	DEVICE_TYPE_TUNEMU,
#endif
} device_type_t;

int device_fd = -1;
char *device = NULL;
char *iface = NULL;
static char *device_info = NULL;
#if defined(ENABLE_TUNEMU)
static device_type_t device_type = DEVICE_TYPE_TUNEMU;
#elif defined(HAVE_OPENBSD) || defined(HAVE_FREEBSD) || defined(HAVE_DRAGONFLY)
static device_type_t device_type = DEVICE_TYPE_TUNIFHEAD;
#else
static device_type_t device_type = DEVICE_TYPE_TUN;
#endif

static bool setup_device(void) {
	get_config_string(lookup_config(config_tree, "Device"), &device);

	char *type;
	if(get_config_string(lookup_config(config_tree, "DeviceType"), &type)) {
		if(!strcasecmp(type, "tun"))
			/* use default */;
#ifdef ENABLE_TUNEMU
		else if(!strcasecmp(type, "tunemu"))
			device_type = DEVICE_TYPE_TUNEMU;
#endif
		else if(!strcasecmp(type, "tunnohead"))
			device_type = DEVICE_TYPE_TUN;
		else if(!strcasecmp(type, "tunifhead"))
			device_type = DEVICE_TYPE_TUNIFHEAD;
		else if(!strcasecmp(type, "tap"))
			device_type = DEVICE_TYPE_TAP;
		else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Unknown device type %s!", type);
			return false;
		}
	} else {
		if((device && strstr(device, "tap")) || routing_mode != RMODE_ROUTER)
			device_type = DEVICE_TYPE_TAP;
	}

	if(!device) {
		if(device_type == DEVICE_TYPE_TAP)
			device = xstrdup(DEFAULT_TAP_DEVICE);
		else
			device = xstrdup(DEFAULT_TUN_DEVICE);
	}

	if(!get_config_string(lookup_config(config_tree, "Interface"), &iface))
		iface = NULL;
#ifndef TAPGIFNAME
	if (iface) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Ignoring specified interface name '%s' as device rename is not supported on this platform", iface);
		free(iface);
		iface = NULL;
	}
#endif
	if (!iface)
		iface = xstrdup(strrchr(device, '/') ? strrchr(device, '/') + 1 : device);

	switch(device_type) {
#ifdef ENABLE_TUNEMU
		case DEVICE_TYPE_TUNEMU: {
			char dynamic_name[256] = "";
			device_fd = tunemu_open(dynamic_name);
		}
			break;
#endif
		default:
			device_fd = open(device, O_RDWR | O_NONBLOCK);
	}

	if(device_fd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open %s: %s", device, strerror(errno));
		return false;
	}

#ifdef FD_CLOEXEC
	fcntl(device_fd, F_SETFD, FD_CLOEXEC);
#endif

	switch(device_type) {
		default:
			device_type = DEVICE_TYPE_TUN;
		case DEVICE_TYPE_TUN:
#ifdef TUNSIFHEAD
		{
			const int zero = 0;
			if(ioctl(device_fd, TUNSIFHEAD, &zero, sizeof zero) == -1) {
				logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "ioctl", strerror(errno));
				return false;
			}
		}
#endif
#if defined(TUNSIFMODE) && defined(IFF_BROADCAST) && defined(IFF_MULTICAST)
		{
			const int mode = IFF_BROADCAST | IFF_MULTICAST;
			ioctl(device_fd, TUNSIFMODE, &mode, sizeof mode);
		}
#endif

			device_info = "Generic BSD tun device";
			break;
		case DEVICE_TYPE_TUNIFHEAD:
#ifdef TUNSIFHEAD
		{
			const int one = 1;
			if(ioctl(device_fd, TUNSIFHEAD, &one, sizeof one) == -1) {
				logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "ioctl", strerror(errno));
				return false;
			}
		}
#endif
#if defined(TUNSIFMODE) && defined(IFF_BROADCAST) && defined(IFF_MULTICAST)
		{
				const int mode = IFF_BROADCAST | IFF_MULTICAST;
				ioctl(device_fd, TUNSIFMODE, &mode, sizeof mode);
		}
#endif

			device_info = "Generic BSD tun device";
			break;
		case DEVICE_TYPE_TAP:
			if(routing_mode == RMODE_ROUTER)
				overwrite_mac = true;
			device_info = "Generic BSD tap device";
#ifdef TAPGIFNAME
			{
				struct ifreq ifr;
				if(ioctl(device_fd, TAPGIFNAME, (void*)&ifr) == 0) {
					if(iface)
						free(iface);
					iface = xstrdup(ifr.ifr_name);
				}
			}

#endif
			break;
#ifdef ENABLE_TUNEMU
		case DEVICE_TYPE_TUNEMU:
			device_info = "BSD tunemu device";
			break;
#endif
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "%s is a %s", device, device_info);

	return true;
}

static void close_device(void) {
	switch(device_type) {
#ifdef ENABLE_TUNEMU
		case DEVICE_TYPE_TUNEMU:
			tunemu_close(device_fd);
			break;
#endif
		default:
			close(device_fd);
	}
	device_fd = -1;

	free(device); device = NULL;
	free(iface); iface = NULL;
	device_info = NULL;
}

static bool read_packet(vpn_packet_t *packet) {
	int inlen;

	switch(device_type) {
		case DEVICE_TYPE_TUN:
#ifdef ENABLE_TUNEMU
		case DEVICE_TYPE_TUNEMU:
			if(device_type == DEVICE_TYPE_TUNEMU)
				inlen = tunemu_read(device_fd, DATA(packet) + 14, MTU - 14);
			else
#endif
				inlen = read(device_fd, DATA(packet) + 14, MTU - 14);

			if(inlen <= 0) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Error while reading from %s %s: %s", device_info,
					   device, strerror(errno));
				return false;
			}

			switch(DATA(packet)[14] >> 4) {
				case 4:
					DATA(packet)[12] = 0x08;
					DATA(packet)[13] = 0x00;
					break;
				case 6:
					DATA(packet)[12] = 0x86;
					DATA(packet)[13] = 0xDD;
					break;
				default:
					logger(DEBUG_TRAFFIC, LOG_ERR,
							   "Unknown IP version %d while reading packet from %s %s",
							   DATA(packet)[14] >> 4, device_info, device);
					return false;
			}

			memset(DATA(packet), 0, 12);
			packet->len = inlen + 14;
			break;

		case DEVICE_TYPE_TUNIFHEAD: {
			u_int32_t type;
			struct iovec vector[2] = {{&type, sizeof type}, {DATA(packet) + 14, MTU - 14}};

			if((inlen = readv(device_fd, vector, 2)) <= 0) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Error while reading from %s %s: %s", device_info,
					   device, strerror(errno));
				return false;
			}

			switch (ntohl(type)) {
				case AF_INET:
					DATA(packet)[12] = 0x08;
					DATA(packet)[13] = 0x00;
					break;

				case AF_INET6:
					DATA(packet)[12] = 0x86;
					DATA(packet)[13] = 0xDD;
					break;

				default:
					logger(DEBUG_TRAFFIC, LOG_ERR,
							   "Unknown address family %x while reading packet from %s %s",
							   ntohl(type), device_info, device);
					return false;
			}

			memset(DATA(packet), 0, 12);
			packet->len = inlen + 10;
			break;
		}

		case DEVICE_TYPE_TAP:
			if((inlen = read(device_fd, DATA(packet), MTU)) <= 0) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Error while reading from %s %s: %s", device_info,
					   device, strerror(errno));
				return false;
			}

			packet->len = inlen;
			break;

		default:
			return false;
	}

	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Read packet of %d bytes from %s",
			   packet->len, device_info);

	return true;
}

static bool write_packet(vpn_packet_t *packet) {
	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Writing packet of %d bytes to %s",
			   packet->len, device_info);

	switch(device_type) {
		case DEVICE_TYPE_TUN:
			if(write(device_fd, DATA(packet) + 14, packet->len - 14) < 0) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Error while writing to %s %s: %s", device_info,
					   device, strerror(errno));
				return false;
			}
			break;

		case DEVICE_TYPE_TUNIFHEAD: {
			u_int32_t type;
			struct iovec vector[2] = {{&type, sizeof type}, {DATA(packet) + 14, packet->len - 14}};
			int af;

			af = (DATA(packet)[12] << 8) + DATA(packet)[13];

			switch (af) {
				case 0x0800:
					type = htonl(AF_INET);
					break;
				case 0x86DD:
					type = htonl(AF_INET6);
					break;
				default:
					logger(DEBUG_TRAFFIC, LOG_ERR,
							   "Unknown address family %x while writing packet to %s %s",
							   af, device_info, device);
					return false;
			}

			if(writev(device_fd, vector, 2) < 0) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Can't write to %s %s: %s", device_info, device,
					   strerror(errno));
				return false;
			}
			break;
		}

		case DEVICE_TYPE_TAP:
			if(write(device_fd, DATA(packet), packet->len) < 0) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Error while writing to %s %s: %s", device_info,
					   device, strerror(errno));
				return false;
			}
			break;

#ifdef ENABLE_TUNEMU
		case DEVICE_TYPE_TUNEMU:
			if(tunemu_write(device_fd, DATA(packet) + 14, packet->len - 14) < 0) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Error while writing to %s %s: %s", device_info,
					   device, strerror(errno));
				return false;
			}
			break;
#endif

		default:
			return false;
	}

	return true;
}

const devops_t os_devops = {
	.setup = setup_device,
	.close = close_device,
	.read = read_packet,
	.write = write_packet,
};
