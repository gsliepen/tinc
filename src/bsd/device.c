/*
    device.c -- Interaction BSD tun/tap device
    Copyright (C) 2001-2005 Ivo Timmermans,
                  2001-2016 Guus Sliepen <guus@tinc-vpn.org>
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
#include "../net.h"
#include "../route.h"
#include "../utils.h"
#include "../xalloc.h"

#ifdef ENABLE_TUNEMU
#include "tunemu.h"
#endif

#ifdef HAVE_NET_IF_UTUN_H
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>
#endif

#define DEFAULT_TUN_DEVICE "/dev/tun0"
#define DEFAULT_TAP_DEVICE "/dev/tap0"

typedef enum device_type {
	DEVICE_TYPE_TUN,
	DEVICE_TYPE_TUNIFHEAD,
	DEVICE_TYPE_TAP,
#ifdef ENABLE_TUNEMU
	DEVICE_TYPE_TUNEMU,
#endif
	DEVICE_TYPE_UTUN,
} device_type_t;

int device_fd = -1;
char *device = NULL;
char *iface = NULL;
static const char *device_info = "OS X utun device";
static uint64_t device_total_in = 0;
static uint64_t device_total_out = 0;
#if defined(ENABLE_TUNEMU)
static device_type_t device_type = DEVICE_TYPE_TUNEMU;
#elif defined(HAVE_OPENBSD) || defined(HAVE_FREEBSD) || defined(HAVE_DRAGONFLY)
static device_type_t device_type = DEVICE_TYPE_TUNIFHEAD;
#else
static device_type_t device_type = DEVICE_TYPE_TUN;
#endif

#ifdef HAVE_NET_IF_UTUN_H
static bool setup_utun(void) {
	device_fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

	if(device_fd == -1) {
		logger(LOG_ERR, "Could not open PF_SYSTEM socket: %s\n", strerror(errno));
		return false;
	}

	struct ctl_info info = {};

	strlcpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));

	if(ioctl(device_fd, CTLIOCGINFO, &info) == -1) {
		logger(LOG_ERR, "ioctl(CTLIOCGINFO) failed: %s", strerror(errno));
		return false;
	}

	int unit = -1;
	char *p = strstr(device, "utun"), *e = NULL;

	if(p) {
		unit = strtol(p + 4, &e, 10);

		if(!e) {
			unit = -1;
		}
	}

	struct sockaddr_ctl sc = {
		.sc_id = info.ctl_id,
		.sc_len = sizeof(sc),
		.sc_family = AF_SYSTEM,
		.ss_sysaddr = AF_SYS_CONTROL,
		.sc_unit = unit + 1,
	};

	if(connect(device_fd, (struct sockaddr *)&sc, sizeof(sc)) == -1) {
		logger(LOG_ERR, "Could not connect utun socket: %s\n", strerror(errno));
		return false;
	}

	char name[64] = "";
	socklen_t len = sizeof(name);

	if(getsockopt(device_fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, &len)) {
		iface = xstrdup(device);
	} else {
		iface = xstrdup(name);
	}

	logger(LOG_INFO, "%s is a %s", device, device_info);

	return true;
}
#endif

static bool setup_device(void) {
	// Find out which device file to open

	if(!get_config_string(lookup_config(config_tree, "Device"), &device)) {
		if(routing_mode == RMODE_ROUTER) {
			device = xstrdup(DEFAULT_TUN_DEVICE);
		} else {
			device = xstrdup(DEFAULT_TAP_DEVICE);
		}
	}

	// Find out if it's supposed to be a tun or a tap device

	char *type;

	if(get_config_string(lookup_config(config_tree, "DeviceType"), &type)) {
		if(!strcasecmp(type, "tun"))
			/* use default */;

#ifdef ENABLE_TUNEMU
		else if(!strcasecmp(type, "tunemu")) {
			device_type = DEVICE_TYPE_TUNEMU;
		}

#endif
#ifdef HAVE_NET_IF_UTUN_H
		else if(!strcasecmp(type, "utun")) {
			device_type = DEVICE_TYPE_UTUN;
		}

#endif
		else if(!strcasecmp(type, "tunnohead")) {
			device_type = DEVICE_TYPE_TUN;
		} else if(!strcasecmp(type, "tunifhead")) {
			device_type = DEVICE_TYPE_TUNIFHEAD;
		} else if(!strcasecmp(type, "tap")) {
			device_type = DEVICE_TYPE_TAP;
		} else {
			logger(LOG_ERR, "Unknown device type %s!", type);
			return false;
		}
	} else {
#ifdef HAVE_NET_IF_UTUN_H

		if(strncmp(device, "utun", 4) == 0 || strncmp(device, "/dev/utun", 9) == 0) {
			device_type = DEVICE_TYPE_UTUN;
		} else
#endif
			if(strstr(device, "tap") || routing_mode != RMODE_ROUTER) {
				device_type = DEVICE_TYPE_TAP;
			}
	}

	if(routing_mode == RMODE_SWITCH && device_type != DEVICE_TYPE_TAP) {
		logger(LOG_ERR, "Only tap devices support switch mode!");
		return false;
	}

	// Open the device

	switch(device_type) {
#ifdef ENABLE_TUNEMU

	case DEVICE_TYPE_TUNEMU: {
		char dynamic_name[256] = "";
		device_fd = tunemu_open(dynamic_name);
	}
	break;
#endif
#ifdef HAVE_NET_IF_UTUN_H

	case DEVICE_TYPE_UTUN:
		return setup_utun();
#endif

	default:
		device_fd = open(device, O_RDWR | O_NONBLOCK);
	}

	if(device_fd < 0) {
		logger(LOG_ERR, "Could not open %s: %s", device, strerror(errno));
		return false;
	}

#ifdef FD_CLOEXEC
	fcntl(device_fd, F_SETFD, FD_CLOEXEC);
#endif

	// Guess what the corresponding interface is called

	char *realname = NULL;

#if defined(HAVE_FDEVNAME)
	realname = fdevname(device_fd);
#elif defined(HAVE_DEVNAME)
	struct stat buf;

	if(!fstat(device_fd, &buf)) {
		realname = devname(buf.st_rdev, S_IFCHR);
	}

#endif

	if(!realname) {
		realname = device;
	}

	if(!get_config_string(lookup_config(config_tree, "Interface"), &iface)) {
		iface = xstrdup(strrchr(realname, '/') ? strrchr(realname, '/') + 1 : realname);
	} else if(strcmp(iface, strrchr(realname, '/') ? strrchr(realname, '/') + 1 : realname)) {
		logger(LOG_WARNING, "Warning: Interface does not match Device. $INTERFACE might be set incorrectly.");
	}

	// Configure the device as best as we can

	switch(device_type) {
	default:
		device_type = DEVICE_TYPE_TUN;

	case DEVICE_TYPE_TUN:
#ifdef TUNSIFHEAD
		{
			const int zero = 0;

			if(ioctl(device_fd, TUNSIFHEAD, &zero, sizeof(zero)) == -1) {
				logger(LOG_ERR, "System call `%s' failed: %s", "ioctl", strerror(errno));
				return false;
			}
		}

#endif
#if defined(TUNSIFMODE) && defined(IFF_BROADCAST) && defined(IFF_MULTICAST)
		{
			const int mode = IFF_BROADCAST | IFF_MULTICAST;
			ioctl(device_fd, TUNSIFMODE, &mode, sizeof(mode));
		}
#endif

		device_info = "Generic BSD tun device";
		break;

	case DEVICE_TYPE_TUNIFHEAD:
#ifdef TUNSIFHEAD
		{
			const int one = 1;

			if(ioctl(device_fd, TUNSIFHEAD, &one, sizeof(one)) == -1) {
				logger(LOG_ERR, "System call `%s' failed: %s", "ioctl", strerror(errno));
				return false;
			}
		}

#endif
#if defined(TUNSIFMODE) && defined(IFF_BROADCAST) && defined(IFF_MULTICAST)
		{
			const int mode = IFF_BROADCAST | IFF_MULTICAST;
			ioctl(device_fd, TUNSIFMODE, &mode, sizeof(mode));
		}
#endif

		device_info = "Generic BSD tun device";
		break;

	case DEVICE_TYPE_TAP:
		if(routing_mode == RMODE_ROUTER) {
			overwrite_mac = true;
		}

		device_info = "Generic BSD tap device";
#ifdef TAPGIFNAME
		{
			struct ifreq ifr;

			if(ioctl(device_fd, TAPGIFNAME, (void *)&ifr) == 0) {
				if(iface) {
					free(iface);
				}

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

#ifdef SIOCGIFADDR

	if(overwrite_mac) {
		ioctl(device_fd, SIOCGIFADDR, mymac.x);
	}

#endif

	logger(LOG_INFO, "%s is a %s", device, device_info);

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

	free(device);
	free(iface);
}

static bool read_packet(vpn_packet_t *packet) {
	int lenin;

	switch(device_type) {
	case DEVICE_TYPE_TUN:
#ifdef ENABLE_TUNEMU
	case DEVICE_TYPE_TUNEMU:
		if(device_type == DEVICE_TYPE_TUNEMU) {
			lenin = tunemu_read(device_fd, packet->data + 14, MTU - 14);
		} else
#endif
			lenin = read(device_fd, packet->data + 14, MTU - 14);

		if(lenin <= 0) {
			logger(LOG_ERR, "Error while reading from %s %s: %s", device_info,
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
			ifdebug(TRAFFIC) logger(LOG_ERR,
			                        "Unknown IP version %d while reading packet from %s %s",
			                        packet->data[14] >> 4, device_info, device);
			return false;
		}

		memset(packet->data, 0, 12);
		packet->len = lenin + 14;
		break;

	case DEVICE_TYPE_UTUN:
	case DEVICE_TYPE_TUNIFHEAD: {
		if((lenin = read(device_fd, packet->data + 10, MTU - 10)) <= 0) {
			logger(LOG_ERR, "Error while reading from %s %s: %s", device_info,
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
			ifdebug(TRAFFIC) logger(LOG_ERR,
			                        "Unknown IP version %d while reading packet from %s %s",
			                        packet->data[14] >> 4, device_info, device);
			return false;
		}

		memset(packet->data, 0, 12);
		packet->len = lenin + 10;
		break;
	}

	case DEVICE_TYPE_TAP:
		if((lenin = read(device_fd, packet->data, MTU)) <= 0) {
			logger(LOG_ERR, "Error while reading from %s %s: %s", device_info,
			       device, strerror(errno));
			return false;
		}

		packet->len = lenin;
		break;

	default:
		return false;
	}

	device_total_in += packet->len;

	ifdebug(TRAFFIC) logger(LOG_DEBUG, "Read packet of %d bytes from %s",
	                        packet->len, device_info);

	return true;
}

static bool write_packet(vpn_packet_t *packet) {
	ifdebug(TRAFFIC) logger(LOG_DEBUG, "Writing packet of %d bytes to %s",
	                        packet->len, device_info);

	switch(device_type) {
	case DEVICE_TYPE_TUN:
		if(write(device_fd, packet->data + 14, packet->len - 14) < 0) {
			logger(LOG_ERR, "Error while writing to %s %s: %s", device_info,
			       device, strerror(errno));
			return false;
		}

		break;

	case DEVICE_TYPE_UTUN:
	case DEVICE_TYPE_TUNIFHEAD: {
		int af = (packet->data[12] << 8) + packet->data[13];
		uint32_t type;

		switch(af) {
		case 0x0800:
			type = htonl(AF_INET);
			break;

		case 0x86DD:
			type = htonl(AF_INET6);
			break;

		default:
			ifdebug(TRAFFIC) logger(LOG_ERR,
			                        "Unknown address family %x while writing packet to %s %s",
			                        af, device_info, device);
			return false;
		}

		memcpy(packet->data + 10, &type, sizeof(type));

		if(write(device_fd, packet->data + 10, packet->len - 10) < 0) {
			logger(LOG_ERR, "Can't write to %s %s: %s", device_info, device,
			       strerror(errno));
			return false;
		}

		break;
	}

	case DEVICE_TYPE_TAP:
		if(write(device_fd, packet->data, packet->len) < 0) {
			logger(LOG_ERR, "Error while writing to %s %s: %s", device_info,
			       device, strerror(errno));
			return false;
		}

		break;

#ifdef ENABLE_TUNEMU

	case DEVICE_TYPE_TUNEMU:
		if(tunemu_write(device_fd, packet->data + 14, packet->len - 14) < 0) {
			logger(LOG_ERR, "Error while writing to %s %s: %s", device_info,
			       device, strerror(errno));
			return false;
		}

		break;
#endif

	default:
		return false;
	}

	device_total_out += packet->len;

	return true;
}

static void dump_device_stats(void) {
	logger(LOG_DEBUG, "Statistics for %s %s:", device_info, device);
	logger(LOG_DEBUG, " total bytes in:  %10"PRIu64, device_total_in);
	logger(LOG_DEBUG, " total bytes out: %10"PRIu64, device_total_out);
}

const devops_t os_devops = {
	.setup = setup_device,
	.close = close_device,
	.read = read_packet,
	.write = write_packet,
	.dump_stats = dump_device_stats,
};
