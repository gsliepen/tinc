/*
    device.c -- Interaction with Windows tap driver in a MinGW environment
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

#include <windows.h>
#include <winioctl.h>

#include "conf.h"
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

extern char *myport;

static DWORD WINAPI tapreader(void *bla) {
	int status;
	long len;
	OVERLAPPED overlapped;
	vpn_packet_t packet;

	logger(LOG_DEBUG, "Tap reader running");

	/* Read from tap device and send to parent */

	overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	for(;;) {
		overlapped.Offset = 0;
		overlapped.OffsetHigh = 0;
		ResetEvent(overlapped.hEvent);

		status = ReadFile(device_handle, packet.data, MTU, &len, &overlapped);

		if(!status) {
			if(GetLastError() == ERROR_IO_PENDING) {
				WaitForSingleObject(overlapped.hEvent, INFINITE);
				if(!GetOverlappedResult(device_handle, &overlapped, &len, FALSE))
					continue;
			} else {
				logger(LOG_ERR, "Error while reading from %s %s: %s", device_info,
					   device, strerror(errno));
				return -1;
			}
		}

		EnterCriticalSection(&mutex);
		packet.len = len;
		packet.priority = 0;
		route(myself, &packet);
		LeaveCriticalSection(&mutex);
	}
}

bool setup_device(void) {
	HKEY key, key2;
	int i;

	char regpath[1024];
	char adapterid[1024];
	char adaptername[1024];
	char tapname[1024];
	long len;
	unsigned long status;

	bool found = false;

	int err;
	HANDLE thread;

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
		device_handle = CreateFile(tapname, GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
		if(device_handle != INVALID_HANDLE_VALUE) {
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

	/* Try to open the corresponding tap device */

	if(device_handle == INVALID_HANDLE_VALUE) {
		snprintf(tapname, sizeof(tapname), USERMODEDEVICEDIR "%s" TAPSUFFIX, device);
		device_handle = CreateFile(tapname, GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
	}
	
	if(device_handle == INVALID_HANDLE_VALUE) {
		logger(LOG_ERR, "%s (%s) is not a usable Windows tap device: %s", device, iface, winerror(GetLastError()));
		return false;
	}

	/* Get MAC address from tap device */

	if(!DeviceIoControl(device_handle, TAP_IOCTL_GET_MAC, mymac.x, sizeof(mymac.x), mymac.x, sizeof(mymac.x), &len, 0)) {
		logger(LOG_ERR, "Could not get MAC address from Windows tap device %s (%s): %s", device, iface, winerror(GetLastError()));
		return false;
	}

	if(routing_mode == RMODE_ROUTER) {
		overwrite_mac = 1;
	}

	/* Start the tap reader */

	thread = CreateThread(NULL, 0, tapreader, NULL, 0, NULL);

	if(!thread) {
		logger(LOG_ERR, "System call `%s' failed: %s", "CreateThread", winerror(GetLastError()));
		return false;
	}

	/* Set media status for newer TAP-Win32 devices */

	status = true;
	DeviceIoControl(device_handle, TAP_IOCTL_SET_MEDIA_STATUS, &status, sizeof(status), &status, sizeof(status), &len, NULL);

	device_info = "Windows tap device";

	logger(LOG_INFO, "%s (%s) is a %s", device, iface, device_info);

	return true;
}

void close_device(void) {
	CloseHandle(device_handle);

	free(device);
	free(iface);
}

bool read_packet(vpn_packet_t *packet) {
	return false;
}

bool write_packet(vpn_packet_t *packet) {
	long lenout;
	OVERLAPPED overlapped = {0};

	ifdebug(TRAFFIC) logger(LOG_DEBUG, "Writing packet of %d bytes to %s",
			   packet->len, device_info);

	if(!WriteFile(device_handle, packet->data, packet->len, &lenout, &overlapped)) {
		logger(LOG_ERR, "Error while writing to %s %s: %s", device_info, device, winerror(GetLastError()));
		return false;
	}

	device_total_out += packet->len;

	return true;
}

void dump_device_stats(void) {
	logger(LOG_DEBUG, "Statistics for %s %s:", device_info, device);
	logger(LOG_DEBUG, " total bytes in:  %10"PRIu64, device_total_in);
	logger(LOG_DEBUG, " total bytes out: %10"PRIu64, device_total_out);
}
