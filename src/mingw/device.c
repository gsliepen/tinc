/*
    device.c -- Interaction with CIPE driver in a MinGW environment
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

    $Id: device.c,v 1.1.2.3 2003/07/28 21:54:03 guus Exp $
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

#define NETCARD_REG_KEY_2000 "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define NETCARD_REG_KEY      "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards"
#define REG_SERVICE_KEY      "SYSTEM\\CurrentControlSet\\Services"
#define REG_CONTROL_NET      "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

#define USERMODEDEVICEDIR "\\\\.\\"
#define SYSDEVICEDIR  "\\Device\\"
#define USERDEVICEDIR "\\??\\"
#define TAPSUFFIX     ".tap"

#define TAP_CONTROL_CODE(request,method) CTL_CODE(FILE_DEVICE_PHYSICAL_NETCARD | 8000, request, method, FILE_ANY_ACCESS)

#define TAP_IOCTL_GET_LASTMAC    TAP_CONTROL_CODE(0, METHOD_BUFFERED)
#define TAP_IOCTL_GET_MAC        TAP_CONTROL_CODE(1, METHOD_BUFFERED)
#define TAP_IOCTL_SET_STATISTICS TAP_CONTROL_CODE(2, METHOD_BUFFERED)

/* FIXME: This only works for Windows 2000 */
#define OSTYPE 5

HANDLE device_fd = INVALID_HANDLE_VALUE;
char *device = NULL;
char *iface = NULL;
char *device_info = NULL;

int device_total_in = 0;
int device_total_out = 0;

bool setup_device(void)
{
	HKEY key, key2;
	int i;

	char regpath[1024];
	char adapterid[1024];
	char adaptername[1024];
	char tapname[1024];
	char gelukt = 0;
	long len;

	bool found = false;

	cp();

	get_config_string(lookup_config(config_tree, "Device"), &device);
	get_config_string(lookup_config(config_tree, "Interface"), &iface);

	/* Open registry and look for network adapters */

	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, REG_CONTROL_NET, 0, KEY_READ, &key)) {
		logger(LOG_ERR, _("Unable to read registry"));
		return false;
	}

	for (i = 0; ; i++) {
		len = sizeof(adapterid);
		if(RegEnumKeyEx(key, i, adapterid, &len, 0, 0, 0, NULL))
			break;

		if(device) {
			if(!strcmp(device, adapterid)) {
				found = true;
				break;
			} else
				continue;
		}

		/* Find out more about this adapter */

		snprintf(regpath, sizeof(regpath), "%s\\%s\\Connection", REG_CONTROL_NET, adapterid);

                if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, regpath, 0, KEY_READ, &key2)) {
			logger(LOG_ERR, _("Unable to read registry"));
			return false;
		}

		len = sizeof(adaptername);
		RegQueryValueEx(key2, "Name", 0, 0, adaptername, &len);

		if(iface) {
			if(!strcmp(iface, adaptername)) {
				found = true;
				break;
			} else
				continue;
		}

		snprintf(tapname, sizeof(tapname), USERMODEDEVICEDIR "%s" TAPSUFFIX, adapterid);
		device_fd = CreateFile(tapname, GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
		if(device_fd != INVALID_HANDLE_VALUE) {
			found = true;
			break;
		}
	}

	if(!found) {
		logger(LOG_ERR, _("No Windows tap device found!"));
		return false;
	}

	device = adapterid;
	iface = adaptername;

	/* Try to open the corresponding tap device */

	if(device_fd == INVALID_HANDLE_VALUE) {
		snprintf(tapname, sizeof(tapname), USERMODEDEVICEDIR "%s" TAPSUFFIX, device);
		device_fd = CreateFile(tapname, GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	}
	
	if(device_fd == INVALID_HANDLE_VALUE) {
		logger(LOG_ERR, _("%s (%s) is no a usable Windows tap device!"), device, iface);
		return false;
	}

	/* Get MAC address from tap device */

	if(DeviceIoControl(device_fd, TAP_IOCTL_GET_MAC, mymac.x, sizeof(mymac.x), mymac.x, sizeof(mymac.x), &len, 0)) {
		logger(LOG_ERR, _("Could not get MAC address from Windows tap device!"));
		return false;
	}

	if(routing_mode == RMODE_ROUTER) {
		overwrite_mac = 1;
	}

	if(!get_config_string(lookup_config(config_tree, "Interface"), &iface))
		iface = device;

	device_info = _("Windows tap device");

	logger(LOG_INFO, _("%s (%s) is a %s"), device, iface, device_info);

	return true;
}

void close_device(void)
{
	cp();

	CloseHandle(device_fd);
}

bool read_packet(vpn_packet_t *packet)
{
	int lenin;

	cp();

	if(!ReadFile(device_fd, packet->data, MTU, &lenin, NULL)) {
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
	int lenout;

	cp();

	ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Writing packet of %d bytes to %s"),
			   packet->len, device_info);

	if(!WriteFile(device_fd, packet->data, packet->len, &lenout, NULL)) {
		logger(LOG_ERR, "Error while writing to %s %s", device_info, device);
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
