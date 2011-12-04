/*
    device.c -- Interaction with Windows tap driver in a Cygwin environment
    Copyright (C) 2002-2005 Ivo Timmermans,
                  2002-2011 Guus Sliepen <guus@tinc-vpn.org>

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

#include <w32api/windows.h>
#include <w32api/winioctl.h>

#include "conf.h"
#include "device.h"
#include "logger.h"
#include "net.h"
#include "route.h"
#include "utils.h"
#include "xalloc.h"

#include "mingw/common.h"

int device_fd = -1;
static HANDLE device_handle = INVALID_HANDLE_VALUE;
char *device = NULL;
char *iface = NULL;
static char *device_info = NULL;

static uint64_t device_total_in = 0;
static uint64_t device_total_out = 0;

static pid_t reader_pid;
static int sp[2];

static bool setup_device(void) {
	HKEY key, key2;
	int i, err;

	char regpath[1024];
	char adapterid[1024];
	char adaptername[1024];
	char tapname[1024];
	char gelukt = 0;
	long len;

	bool found = false;

	get_config_string(lookup_config(config_tree, "Device"), &device);
	get_config_string(lookup_config(config_tree, "Interface"), &iface);

	/* Open registry and look for network adapters */

	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, NETWORK_CONNECTIONS_KEY, 0, KEY_READ, &key)) {
		logger(LOG_ERR, "Unable to read registry: %s", winerror(GetLastError()));
		return false;
	}

	for (i = 0; ; i++) {
		len = sizeof(adapterid);
		if(RegEnumKeyEx(key, i, adapterid, &len, 0, 0, 0, NULL))
			break;

		/* Find out more about this adapter */

		snprintf(regpath, sizeof(regpath), "%s\\%s\\Connection", NETWORK_CONNECTIONS_KEY, adapterid);

                if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, regpath, 0, KEY_READ, &key2))
			continue;

		len = sizeof(adaptername);
		err = RegQueryValueEx(key2, "Name", 0, 0, adaptername, &len);

		RegCloseKey(key2);

		if(err)
			continue;

		if(device) {
			if(!strcmp(device, adapterid)) {
				found = true;
				break;
			} else
				continue;
		}

		if(iface) {
			if(!strcmp(iface, adaptername)) {
				found = true;
				break;
			} else
				continue;
		}

		snprintf(tapname, sizeof(tapname), USERMODEDEVICEDIR "%s" TAPSUFFIX, adapterid);
		device_handle = CreateFile(tapname, GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
		if(device_handle != INVALID_HANDLE_VALUE) {
			CloseHandle(device_handle);
			found = true;
			break;
		}
	}

	RegCloseKey(key);

	if(!found) {
		logger(LOG_ERR, "No Windows tap device found!");
		return false;
	}

	if(!device)
		device = xstrdup(adapterid);

	if(!iface)
		iface = xstrdup(adaptername);

	snprintf(tapname, sizeof(tapname), USERMODEDEVICEDIR "%s" TAPSUFFIX, device);
	
	/* Now we are going to open this device twice: once for reading and once for writing.
	   We do this because apparently it isn't possible to check for activity in the select() loop.
	   Furthermore I don't really know how to do it the "Windows" way. */

	if(socketpair(AF_UNIX, SOCK_DGRAM, PF_UNIX, sp)) {
		logger(LOG_DEBUG, "System call `%s' failed: %s", "socketpair", strerror(errno));
		return false;
	}

	/* The parent opens the tap device for writing. */
	
	device_handle = CreateFile(tapname, GENERIC_WRITE,  FILE_SHARE_READ,  0,  OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM , 0);
	
	if(device_handle == INVALID_HANDLE_VALUE) {
		logger(LOG_ERR, "Could not open Windows tap device %s (%s) for writing: %s", device, iface, winerror(GetLastError()));
		return false;
	}

	device_fd = sp[0];

	/* Get MAC address from tap device */

	if(!DeviceIoControl(device_handle, TAP_IOCTL_GET_MAC, mymac.x, sizeof(mymac.x), mymac.x, sizeof(mymac.x), &len, 0)) {
		logger(LOG_ERR, "Could not get MAC address from Windows tap device %s (%s): %s", device, iface, winerror(GetLastError()));
		return false;
	}

	if(routing_mode == RMODE_ROUTER) {
		overwrite_mac = 1;
	}

	/* Now we start the child */

	reader_pid = fork();

	if(reader_pid == -1) {
		logger(LOG_DEBUG, "System call `%s' failed: %s", "fork", strerror(errno));
		return false;
	}

	if(!reader_pid) {
		/* The child opens the tap device for reading, blocking.
		   It passes everything it reads to the socket. */
	
		char buf[MTU];
		long lenin;

		CloseHandle(device_handle);

		device_handle = CreateFile(tapname, GENERIC_READ, FILE_SHARE_WRITE, 0,  OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);

		if(device_handle == INVALID_HANDLE_VALUE) {
			logger(LOG_ERR, "Could not open Windows tap device %s (%s) for reading: %s", device, iface, winerror(GetLastError()));
			buf[0] = 0;
			write(sp[1], buf, 1);
			exit(1);
		}

		logger(LOG_DEBUG, "Tap reader forked and running.");

		/* Notify success */

		buf[0] = 1;
		write(sp[1], buf, 1);

		/* Pass packets */

		for(;;) {
			ReadFile(device_handle, buf, MTU, &lenin, NULL);
			write(sp[1], buf, lenin);
		}
	}

	read(device_fd, &gelukt, 1);
	if(gelukt != 1) {
		logger(LOG_DEBUG, "Tap reader failed!");
		return false;
	}

	device_info = "Windows tap device";

	logger(LOG_INFO, "%s (%s) is a %s", device, iface, device_info);

	return true;
}

static void close_device(void) {
	close(sp[0]);
	close(sp[1]);
	CloseHandle(device_handle);

	kill(reader_pid, SIGKILL);

	free(device);
	free(iface);
}

static bool read_packet(vpn_packet_t *packet) {
	int lenin;

	if((lenin = read(sp[0], packet->data, MTU)) <= 0) {
		logger(LOG_ERR, "Error while reading from %s %s: %s", device_info,
			   device, strerror(errno));
		return false;
	}
	
	packet->len = lenin;

	device_total_in += packet->len;

	ifdebug(TRAFFIC) logger(LOG_DEBUG, "Read packet of %d bytes from %s", packet->len,
			   device_info);

	return true;
}

static bool write_packet(vpn_packet_t *packet) {
	long lenout;

	ifdebug(TRAFFIC) logger(LOG_DEBUG, "Writing packet of %d bytes to %s",
			   packet->len, device_info);

	if(!WriteFile (device_handle, packet->data, packet->len, &lenout, NULL)) {
		logger(LOG_ERR, "Error while writing to %s %s: %s", device_info, device, winerror(GetLastError()));
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
