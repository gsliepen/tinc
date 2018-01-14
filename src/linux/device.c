/*
    device.c -- Interaction with Linux ethertap and tun/tap device
    Copyright (C) 2001-2005 Ivo Timmermans,
                  2001-2014 Guus Sliepen <guus@tinc-vpn.org>

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

#include <assert.h>

#include <sys/eventfd.h>
#include <linux/if_tun.h>
#define DEFAULT_DEVICE "/dev/net/tun"

#include "../async_pool.h"
#include "../conf.h"
#include "../device.h"
#include "../logger.h"
#include "../names.h"
#include "../net.h"
#include "../route.h"
#include "../tinycthread.h"
#include "../utils.h"
#include "../xalloc.h"
#include "../device.h"

typedef enum device_type_t {
	DEVICE_TYPE_TUN,
	DEVICE_TYPE_TAP,
} device_type_t;

#define ASYNC_DEVICE_QUEUE_LENGTH 128

bool active;
thrd_t thrd;
async_pool_t *device_read_pool;
int device_fd = -1;
int real_fd = -1;
static device_type_t device_type;
char *device = NULL;
char *iface = NULL;
static char *type = NULL;
static char ifrname[IFNAMSIZ];
static const char *device_info;

static bool read_packet(vpn_packet_t *packet) {
	int inlen;

	switch(device_type) {
	case DEVICE_TYPE_TUN:
		packet->offset = DEFAULT_PACKET_OFFSET;
		packet->priority = 0;
		inlen = read(real_fd, DATA(packet) + 10, MTU - 10);

		if(inlen <= 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Error while reading from %s %s: %s",
			       device_info, device, strerror(errno));

			if(errno == EBADFD) {  /* File descriptor in bad state */
				event_exit();
			}

			return false;
		}

		memset(DATA(packet), 0, 12);
		packet->len = inlen + 10;
		break;

	case DEVICE_TYPE_TAP:
		inlen = read(real_fd, DATA(packet), MTU);

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

	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Read packet of %d bytes from %s", packet->len,
	       device_info);

	return true;
}

static bool write_packet(vpn_packet_t *packet) {
	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Writing packet of %d bytes to %s",
	       packet->len, device_info);

	switch(device_type) {
	case DEVICE_TYPE_TUN:
		DATA(packet)[10] = DATA(packet)[11] = 0;

		if(write(real_fd, DATA(packet) + 10, packet->len - 10) < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Can't write to %s %s: %s", device_info, device,
			       strerror(errno));
			return false;
		}

		break;

	case DEVICE_TYPE_TAP:
		if(write(real_fd, DATA(packet), packet->len) < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Can't write to %s %s: %s", device_info, device,
			       strerror(errno));
			return false;
		}

		break;

	default:
		abort();
	}

	return true;
}

static int read_thread(void *arg) {
	while(active) {
		vpn_packet_t *packet = async_pool_get(device_read_pool);
		if (read_packet(packet)) {
			async_pool_put(device_read_pool, packet);
			static const uint64_t one = 1;
			assert(write(device_fd, &one, sizeof(one)) == sizeof(one));
		} else {
			abort();
		}
	}
	return 0;
}

static bool setup_device(void) {
	device_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);

	if(device_fd == -1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open %s: %s", device, strerror(errno));
		return false;
	}

	device_read_pool = async_pool_alloc(ASYNC_DEVICE_QUEUE_LENGTH, sizeof(vpn_packet_t), NULL);

	if(!get_config_string(lookup_config(config_tree, "Device"), &device)) {
		device = xstrdup(DEFAULT_DEVICE);
	}

	if(!get_config_string(lookup_config(config_tree, "Interface"), &iface))
		if(netname) {
			iface = xstrdup(netname);
		}

	real_fd = open(device, O_RDWR);

	if(real_fd == -1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open %s: %s", device, strerror(errno));
		return false;
	}

#ifdef FD_CLOEXEC
	fcntl(real_fd, F_SETFD, FD_CLOEXEC);
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
		if(routing_mode == RMODE_ROUTER) {
			overwrite_mac = true;
		}

		ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
		device_type = DEVICE_TYPE_TAP;
		device_info = "Linux tun/tap device (tap mode)";
	}

#ifdef IFF_ONE_QUEUE
	/* Set IFF_ONE_QUEUE flag... */

	bool t1q = false;

	if(get_config_bool(lookup_config(config_tree, "IffOneQueue"), &t1q) && t1q) {
		ifr.ifr_flags |= IFF_ONE_QUEUE;
	}

#endif

	if(iface) {
		strncpy(ifr.ifr_name, iface, IFNAMSIZ);
	}

	if(!ioctl(real_fd, TUNSETIFF, &ifr)) {
		strncpy(ifrname, ifr.ifr_name, IFNAMSIZ);
		free(iface);
		iface = xstrdup(ifrname);
	} else {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not create a tun/tap interface from %s: %s", device, strerror(errno));
		return false;
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "%s is a %s", device, device_info);

	if(ifr.ifr_flags & IFF_TAP) {
		struct ifreq ifr_mac = {{{0}}};

		if(!ioctl(real_fd, SIOCGIFHWADDR, &ifr_mac)) {
			memcpy(mymac.x, ifr_mac.ifr_hwaddr.sa_data, ETH_ALEN);
		} else {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Could not get MAC address of %s: %s", device, strerror(errno));
		}
	}

	active = true;
	thrd = thrd_create(&thrd, read_thread, NULL);

	return true;
}

static void close_device(void) {
	close(real_fd);
	real_fd = -1;
	close(device_fd);
	device_fd = -1;
	if(active) {
		active = false;
		thrd_join(thrd, NULL);
	}

	async_pool_free(device_read_pool);
	device_read_pool = NULL;

	free(type);
	type = NULL;
	free(device);
	device = NULL;
	free(iface);
	iface = NULL;
	device_info = NULL;
}

const devops_t os_devops = {
	.setup = setup_device,
	.close = close_device,
	.read = NULL,
	.write = write_packet,
};
