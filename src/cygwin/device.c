/*
    device.c -- Interaction with Windows tap driver in a Cygwin environment
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

    $Id: device.c,v 1.1.2.13 2003/07/29 12:18:35 guus Exp $
*/

#include "system.h"

#include <w32api/windows.h>
#include <w32api/winioctl.h>

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

int device_fd = -1;
char *device = NULL;
char *iface = NULL;
char *device_info = NULL;

int device_total_in = 0;
int device_total_out = 0;

HANDLE handle;

pid_t reader_pid;
int sp[2];

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

		/* Find out more about this adapter */

		snprintf(regpath, sizeof(regpath), "%s\\%s\\Connection", REG_CONTROL_NET, adapterid);

                if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, regpath, 0, KEY_READ, &key2))
			continue;

		len = sizeof(adaptername);
		RegQueryValueEx(key2, "Name", 0, 0, adaptername, &len);

		RegCloseKey(key2);

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
		handle = CreateFile(tapname, GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
		if(handle != INVALID_HANDLE_VALUE) {
			CloseHandle(handle);
			found = true;
			break;
		}
	}

	RegCloseKey(key);

	if(!found) {
		logger(LOG_ERR, _("No Windows tap device found!"));
		return false;
	}

	device = adapterid;
	iface = adaptername;	

	snprintf(tapname, sizeof(tapname), USERMODEDEVICEDIR "%s" TAPSUFFIX, device);
	
	/* Now we are going to open this device twice: once for reading and once for writing.
	   We do this because apparently it isn't possible to check for activity in the select() loop.
	   Furthermore I don't really know how to do it the "Windows" way. */

	if(socketpair(AF_UNIX, SOCK_DGRAM, PF_UNIX, sp)) {
		logger(LOG_DEBUG, _("System call `%s' failed: %s"), "socketpair", strerror(errno));
		return false;
	}

	/* The parent opens the tap device for writing. */
	
	handle = CreateFile(tapname, GENERIC_WRITE,  FILE_SHARE_READ,  0,  OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM , 0);
	
	if(handle == INVALID_HANDLE_VALUE) {
		logger(LOG_ERR, _("Could not open Windows tap device for writing!"));
		return false;
	}

	device_fd = sp[0];

	/* Get MAC address from tap device */

	if(!DeviceIoControl(handle, TAP_IOCTL_GET_MAC, mymac.x, sizeof(mymac.x), mymac.x, sizeof(mymac.x), &len, 0)) {
		logger(LOG_ERR, _("Could not get MAC address from Windows tap device!"));
		return false;
	}

	if(routing_mode == RMODE_ROUTER) {
		overwrite_mac = 1;
	}

	/* Now we start the child */

	reader_pid = fork();

	if(reader_pid == -1) {
		logger(LOG_DEBUG, _("System call `%s' failed: %s"), "fork", strerror(errno));
		return false;
	}

	if(!reader_pid) {
		/* The child opens the tap device for reading, blocking.
		   It passes everything it reads to the socket. */
	
		char buf[MTU];
		long lenin;

		CloseHandle(handle);

		handle = CreateFile(tapname, GENERIC_READ, FILE_SHARE_WRITE, 0,  OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);

		if(handle == INVALID_HANDLE_VALUE) {
			logger(LOG_ERR, _("Could not open Windows tap device for reading!"));
			buf[0] = 0;
			write(sp[1], buf, 1);
			exit(1);
		}

		logger(LOG_DEBUG, _("Tap reader forked and running."));

		/* Notify success */

		buf[0] = 1;
		write(sp[1], buf, 1);

		/* Pass packets */

		for(;;) {
			ReadFile(handle, buf, MTU, &lenin, NULL);
			write(sp[1], buf, lenin);
		}
	}

	read(device_fd, &gelukt, 1);
	if(gelukt != 1) {
		logger(LOG_DEBUG, _("Tap reader failed!"));
		return false;
	}

	device_info = _("Windows tap device");

	logger(LOG_INFO, _("%s (%s) is a %s"), device, iface, device_info);

	return true;
}

void close_device(void)
{
	cp();

	close(sp[0]);
	close(sp[1]);
	CloseHandle(handle);

	kill(reader_pid, SIGKILL);
}

bool read_packet(vpn_packet_t *packet)
{
	int lenin;

	cp();

	if((lenin = read(sp[0], packet->data, MTU)) <= 0) {
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

	cp();

	ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Writing packet of %d bytes to %s"),
			   packet->len, device_info);

	if(!WriteFile (handle, packet->data, packet->len, &lenout, NULL)) {
		logger(LOG_ERR, _("Error while writing to %s %s"), device_info, device);
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
