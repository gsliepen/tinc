/*
    device.c -- Interaction with Windows tap driver in a MinGW environment
    Copyright (C) 2002-2003 Ivo Timmermans <ivo@o2w.nl>,
                  2002-2003 Guus Sliepen <guus@sliepen.eu.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    $Id: device.c,v 1.3 2003/08/27 13:47:49 guus Exp $
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

#define REG_CONTROL_NET      "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

#define USERMODEDEVICEDIR "\\\\.\\"
#define USERDEVICEDIR "\\??\\"
#define TAPSUFFIX     ".tap"

#define TAP_CONTROL_CODE(request,method) CTL_CODE(FILE_DEVICE_PHYSICAL_NETCARD | 8000, request, method, FILE_ANY_ACCESS)

#define TAP_IOCTL_GET_LASTMAC    TAP_CONTROL_CODE(0, METHOD_BUFFERED)
#define TAP_IOCTL_GET_MAC        TAP_CONTROL_CODE(1, METHOD_BUFFERED)
#define TAP_IOCTL_SET_STATISTICS TAP_CONTROL_CODE(2, METHOD_BUFFERED)

int device_fd = 0;
HANDLE device_handle = INVALID_HANDLE_VALUE;
char *device = NULL;
char *iface = NULL;
char *device_info = NULL;

int device_total_in = 0;
int device_total_out = 0;

extern char *myport;

DWORD WINAPI tapreader(void *bla) {
	int sock, err, status;
	struct addrinfo *ai;
	struct addrinfo hint = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP,
		.ai_flags = 0,
	};
	char buf[MTU];
	long len;
	OVERLAPPED overlapped;

	/* Open a socket to the parent process */

	err = getaddrinfo(NULL, myport, &hint, &ai);

	if(err || !ai) {
		logger(LOG_ERR, _("System call `%s' failed: %s"), "getaddrinfo", gai_strerror(errno));
		return -1;
	}

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

	freeaddrinfo(ai);

	if(sock < 0) {
		logger(LOG_ERR, _("System call `%s' failed: %s"), "socket", strerror(errno));
		return -1;
	}

	if(connect(sock, ai->ai_addr, ai->ai_addrlen)) {
		logger(LOG_ERR, _("System call `%s' failed: %s"), "connect", strerror(errno));
		return -1;
	}

	logger(LOG_DEBUG, _("Tap reader running"));

	/* Read from tap device and send to parent */

	overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	
	for(;;) {
		overlapped.Offset = 0;
		overlapped.OffsetHigh = 0;
		ResetEvent(overlapped.hEvent);

		status = ReadFile(device_handle, buf, sizeof(buf), &len, &overlapped);

		if(!status) {
			if(GetLastError() == ERROR_IO_PENDING) {
				WaitForSingleObject(overlapped.hEvent, INFINITE);
				if(!GetOverlappedResult(device_handle, &overlapped, &len, FALSE))
					continue;
			} else {
				logger(LOG_ERR, _("Error while reading from %s %s: %s"), device_info,
					   device, strerror(errno));
				return -1;
			}
		}

		if(send(sock, buf, len, 0) <= 0)
			return -1;
	}
}

bool setup_device(void)
{
	HKEY key, key2;
	int i;

	char regpath[1024];
	char adapterid[1024];
	char adaptername[1024];
	char tapname[1024];
	long len;

	bool found = false;

	int sock, err;
	HANDLE thread;

	struct addrinfo *ai;
	struct addrinfo hint = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP,
		.ai_flags = 0,
	};

	cp();

	get_config_string(lookup_config(config_tree, "Device"), &device);
	get_config_string(lookup_config(config_tree, "Interface"), &iface);

	/* Open registry and look for network adapters */

	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, REG_CONTROL_NET, 0, KEY_READ, &key)) {
		logger(LOG_ERR, _("Unable to read registry: %s"), winerror(GetLastError()));
		return false;
	}

	for (i = 0; ; i++) {
		len = sizeof(adapterid);
		if(RegEnumKeyEx(key, i, adapterid, &len, 0, 0, 0, NULL))
			break;

		/* Find out more about this adapter */

		snprintf(regpath, sizeof(regpath), "%s\\%s\\Connection", REG_CONTROL_NET, adapterid);

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
		logger(LOG_ERR, _("No Windows tap device found!"));
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
		logger(LOG_ERR, _("%s (%s) is not a usable Windows tap device: %s"), device, iface, winerror(GetLastError()));
		return false;
	}

	/* Get MAC address from tap device */

	if(!DeviceIoControl(device_handle, TAP_IOCTL_GET_MAC, mymac.x, sizeof(mymac.x), mymac.x, sizeof(mymac.x), &len, 0)) {
		logger(LOG_ERR, _("Could not get MAC address from Windows tap device %s (%s): %s"), device, iface, winerror(GetLastError()));
		return false;
	}

	if(routing_mode == RMODE_ROUTER) {
		overwrite_mac = 1;
	}

	/* Create a listening socket */

	err = getaddrinfo(NULL, myport, &hint, &ai);

	if(err || !ai) {
		logger(LOG_ERR, _("System call `%s' failed: %s"), "getaddrinfo", gai_strerror(errno));
		return false;
	}

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

	if(sock < 0) {
		logger(LOG_ERR, _("System call `%s' failed: %s"), "socket", strerror(errno));
		return false;
	}

	if(bind(sock, ai->ai_addr, ai->ai_addrlen)) {
		logger(LOG_ERR, _("System call `%s' failed: %s"), "bind", strerror(errno));
		return false;
	}

	freeaddrinfo(ai);

	if(listen(sock, 1)) {
		logger(LOG_ERR, _("System call `%s' failed: %s"), "listen", strerror(errno));
		return false;
	}

	/* Start the tap reader */

	thread = CreateThread(NULL, 0, tapreader, NULL, 0, NULL);

	if(!thread) {
		logger(LOG_ERR, _("System call `%s' failed: %s"), "CreateThread", winerror(GetLastError()));
		return false;
	}

	/* Wait for the tap reader to connect back to us */

	if((device_fd = accept(sock, NULL, 0)) == -1) {
		logger(LOG_ERR, _("System call `%s' failed: %s"), "accept", strerror(errno));
		return false;
	}

	closesocket(sock);

	device_info = _("Windows tap device");

	logger(LOG_INFO, _("%s (%s) is a %s"), device, iface, device_info);

	return true;
}

void close_device(void)
{
	cp();

	CloseHandle(device_handle);
}

bool read_packet(vpn_packet_t *packet)
{
	int lenin;

	cp();

	if((lenin = recv(device_fd, packet->data, MTU, 0)) <= 0) {
		logger(LOG_ERR, _("Error while reading from %s %s: %s"), device_info,
			   device, strerror(errno));
		return false;
	}
	
	packet->len = lenin;

	device_total_in += packet->len;

	ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Read packet of %d bytes from %s"), packet->len,
			   device_info);

	return true;
}

bool write_packet(vpn_packet_t *packet)
{
	long lenout;
	OVERLAPPED overlapped = {0};

	cp();

	ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Writing packet of %d bytes to %s"),
			   packet->len, device_info);

	if(!WriteFile(device_handle, packet->data, packet->len, &lenout, &overlapped)) {
		logger(LOG_ERR, _("Error while writing to %s %s: %s"), device_info, device, winerror(GetLastError()));
		return false;
	}

	device_total_out += packet->len;

	return true;
}

void dump_device_stats(void)
{
	cp();

	logger(LOG_DEBUG, _("Statistics for %s %s:"), device_info, device);
	logger(LOG_DEBUG, _(" total bytes in:  %10d"), device_total_in);
	logger(LOG_DEBUG, _(" total bytes out: %10d"), device_total_out);
}
