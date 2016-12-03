/*
    device.c -- Interaction with Windows tap driver in a MinGW environment
    Copyright (C) 2002-2005 Ivo Timmermans,
                  2002-2014 Guus Sliepen <guus@tinc-vpn.org>

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

#include <windows.h>
#include <winioctl.h>

#include "../conf.h"
#include "../device.h"
#include "../logger.h"
#include "../names.h"
#include "../net.h"
#include "../route.h"
#include "../utils.h"
#include "../xalloc.h"

#include "common.h"

int device_fd = -1;
static HANDLE device_handle = INVALID_HANDLE_VALUE;
static io_t device_read_io;
static OVERLAPPED device_read_overlapped;
static OVERLAPPED device_write_overlapped;
static vpn_packet_t device_read_packet;
static vpn_packet_t device_write_packet;
char *device = NULL;
char *iface = NULL;
static char *device_info = NULL;

extern char *myport;

static void device_issue_read() {
	device_read_overlapped.Offset = 0;
	device_read_overlapped.OffsetHigh = 0;

	int status;
	for (;;) {
		DWORD len;
		status = ReadFile(device_handle, (void *)device_read_packet.data, MTU, &len, &device_read_overlapped);
		if (!status) {
			if (GetLastError() != ERROR_IO_PENDING)
				logger(DEBUG_ALWAYS, LOG_ERR, "Error while reading from %s %s: %s", device_info,
					   device, strerror(errno));
			break;
		}

		device_read_packet.len = len;
		device_read_packet.priority = 0;
		route(myself, &device_read_packet);
	}
}

static void device_handle_read(void *data, int flags) {
	ResetEvent(device_read_overlapped.hEvent);

	DWORD len;
	if (!GetOverlappedResult(device_handle, &device_read_overlapped, &len, FALSE)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error getting read result from %s %s: %s", device_info,
			   device, strerror(errno));
		return;
	}

	device_read_packet.len = len;
	device_read_packet.priority = 0;
	route(myself, &device_read_packet);
	device_issue_read();
}

static bool setup_device(void) {
	HKEY key, key2;
	int i;

	char regpath[1024];
	char adapterid[1024];
	char adaptername[1024];
	char tapname[1024];
	DWORD len;

	bool found = false;

	int err;

	get_config_string(lookup_config(config_tree, "Device"), &device);
	get_config_string(lookup_config(config_tree, "Interface"), &iface);

	if(device && iface)
		logger(DEBUG_ALWAYS, LOG_WARNING, "Warning: both Device and Interface specified, results may not be as expected");

	/* Open registry and look for network adapters */

	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, NETWORK_CONNECTIONS_KEY, 0, KEY_READ, &key)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to read registry: %s", winerror(GetLastError()));
		return false;
	}

	for (i = 0; ; i++) {
		len = sizeof adapterid;
		if(RegEnumKeyEx(key, i, adapterid, &len, 0, 0, 0, NULL))
			break;

		/* Find out more about this adapter */

		snprintf(regpath, sizeof regpath, "%s\\%s\\Connection", NETWORK_CONNECTIONS_KEY, adapterid);

		if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, regpath, 0, KEY_READ, &key2))
			continue;

		len = sizeof adaptername;
		err = RegQueryValueEx(key2, "Name", 0, 0, (LPBYTE)adaptername, &len);

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

		snprintf(tapname, sizeof tapname, USERMODEDEVICEDIR "%s" TAPSUFFIX, adapterid);
		device_handle = CreateFile(tapname, GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
		if(device_handle != INVALID_HANDLE_VALUE) {
			found = true;
			break;
		}
	}

	RegCloseKey(key);

	if(!found) {
		logger(DEBUG_ALWAYS, LOG_ERR, "No Windows tap device found!");
		return false;
	}

	if(!device)
		device = xstrdup(adapterid);

	if(!iface)
		iface = xstrdup(adaptername);

	/* Try to open the corresponding tap device */

	if(device_handle == INVALID_HANDLE_VALUE) {
		snprintf(tapname, sizeof tapname, USERMODEDEVICEDIR "%s" TAPSUFFIX, device);
		device_handle = CreateFile(tapname, GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
	}

	if(device_handle == INVALID_HANDLE_VALUE) {
		logger(DEBUG_ALWAYS, LOG_ERR, "%s (%s) is not a usable Windows tap device: %s", device, iface, winerror(GetLastError()));
		return false;
	}

	/* Get version information from tap device */

	{
		ULONG info[3] = {0};
		DWORD len;
		if(!DeviceIoControl(device_handle, TAP_IOCTL_GET_VERSION, &info, sizeof info, &info, sizeof info, &len, NULL))
			logger(DEBUG_ALWAYS, LOG_WARNING, "Could not get version information from Windows tap device %s (%s): %s", device, iface, winerror(GetLastError()));
		else {
			logger(DEBUG_ALWAYS, LOG_INFO, "TAP-Windows driver version: %lu.%lu%s", info[0], info[1], info[2] ? " (DEBUG)" : "");

			/* Warn if using >=9.21. This is because starting from 9.21, TAP-Win32 seems to use a different, less efficient write path. */
			if(info[0] == 9 && info[1] >= 21)
				logger(DEBUG_ALWAYS, LOG_WARNING,
					"You are using the newer (>= 9.0.0.21, NDIS6) series of TAP-Win32 drivers. "
					"Using these drivers with tinc is not recommanded as it can result in poor performance. "
					"You might want to revert back to 9.0.0.9 instead.");
		}
	}

	/* Get MAC address from tap device */

	if(!DeviceIoControl(device_handle, TAP_IOCTL_GET_MAC, mymac.x, sizeof mymac.x, mymac.x, sizeof mymac.x, &len, 0)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not get MAC address from Windows tap device %s (%s): %s", device, iface, winerror(GetLastError()));
		return false;
	}

	if(routing_mode == RMODE_ROUTER) {
		overwrite_mac = 1;
	}

	device_info = "Windows tap device";

	logger(DEBUG_ALWAYS, LOG_INFO, "%s (%s) is a %s", device, iface, device_info);

	device_read_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	device_write_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	return true;
}

static void enable_device(void) {
	logger(DEBUG_ALWAYS, LOG_INFO, "Enabling %s", device_info);

	ULONG status = 1;
	DWORD len;
	DeviceIoControl(device_handle, TAP_IOCTL_SET_MEDIA_STATUS, &status, sizeof status, &status, sizeof status, &len, NULL);

	/* We don't use the write event directly, but GetOverlappedResult() does, internally. */

	io_add_event(&device_read_io, device_handle_read, NULL, device_read_overlapped.hEvent);
	device_issue_read();
}

static void disable_device(void) {
	logger(DEBUG_ALWAYS, LOG_INFO, "Disabling %s", device_info);

	io_del(&device_read_io);

	ULONG status = 0;
	DWORD len;
	DeviceIoControl(device_handle, TAP_IOCTL_SET_MEDIA_STATUS, &status, sizeof status, &status, sizeof status, &len, NULL);

	/* Note that we don't try to cancel ongoing I/O here - we just stop listening.
	   This is because some TAP-Win32 drivers don't seem to handle cancellation very well,
	   especially when combined with other events such as the computer going to sleep - cases
	   were observed where the GetOverlappedResult() would just block indefinitely and never
	   return in that case. */
}

static void close_device(void) {
	CancelIo(device_handle);

	/* According to MSDN, CancelIo() does not necessarily wait for the operation to complete.
	   To prevent race conditions, make sure the operation is complete
	   before we close the event it's referencing. */

	DWORD len;
	if(!GetOverlappedResult(device_handle, &device_read_overlapped, &len, TRUE) && GetLastError() != ERROR_OPERATION_ABORTED)
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not wait for %s %s read to cancel: %s", device_info, device, winerror(GetLastError()));
	if(device_write_packet.len > 0 && !GetOverlappedResult(device_handle, &device_write_overlapped, &len, TRUE) && GetLastError() != ERROR_OPERATION_ABORTED)
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not wait for %s %s write to cancel: %s", device_info, device, winerror(GetLastError()));
	device_write_packet.len = 0;

	CloseHandle(device_read_overlapped.hEvent);
	CloseHandle(device_write_overlapped.hEvent);

	CloseHandle(device_handle); device_handle = INVALID_HANDLE_VALUE;

	free(device); device = NULL;
	free(iface); iface = NULL;
	device_info = NULL;
}

static bool read_packet(vpn_packet_t *packet) {
	return false;
}

static bool write_packet(vpn_packet_t *packet) {
	DWORD outlen;

	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Writing packet of %d bytes to %s",
			   packet->len, device_info);

	if(device_write_packet.len > 0) {
		/* Make sure the previous write operation is finished before we start the next one;
		   otherwise we end up with multiple write ops referencing the same OVERLAPPED structure,
		   which according to MSDN is a no-no. */

		if(!GetOverlappedResult(device_handle, &device_write_overlapped, &outlen, FALSE)) {
			int log_level = (GetLastError() == ERROR_IO_INCOMPLETE) ? DEBUG_TRAFFIC : DEBUG_ALWAYS;
			logger(log_level, LOG_ERR, "Error while checking previous write to %s %s: %s", device_info, device, winerror(GetLastError()));
			return false;
		}
	}

	/* Copy the packet, since the write operation might still be ongoing after we return. */

	memcpy(&device_write_packet, packet, sizeof *packet);

	if(WriteFile(device_handle, DATA(&device_write_packet), device_write_packet.len, &outlen, &device_write_overlapped))
		device_write_packet.len = 0;
	else if (GetLastError() != ERROR_IO_PENDING) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while writing to %s %s: %s", device_info, device, winerror(GetLastError()));
		return false;
	}

	return true;
}

const devops_t os_devops = {
	.setup = setup_device,
	.close = close_device,
	.read = read_packet,
	.write = write_packet,
	.enable = enable_device,
	.disable = disable_device,
};
