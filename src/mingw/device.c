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

    $Id: device.c,v 1.1.2.1 2003/07/21 15:51:00 guus Exp $
*/

#error "Device driver for MinGW environment not written yet!"

#include "system.h"

#include <winioctl.h>

#include "conf.h"
#include "logger.h"
#include "net.h"
#include "route.h"
#include "utils.h"
#include "xalloc.h"

/* Definitions from CIPE */

#define NETCARD_REG_KEY_2000 "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define NETCARD_REG_KEY      "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards"
#define REG_SERVICE_KEY      "SYSTEM\\CurrentControlSet\\Services"

#define USERMODEDEVICEDIR "\\\\.\\"
#define SYSDEVICEDIR  "\\Device\\"
#define USERDEVICEDIR "\\??\\"
#define TAPSUFFIX     ".tap"

#define PRODUCT_STRING "DKW Heavy Industries VPN Adapter."
#define CIPE_SERVICE_NAME "CIPE_Daemon"
#define CIPE_DRIVER_NAME "CIPE"

#define CIPE_NDIS_MAJOR_VERSION 4
#define CIPE_NDIS_MINOR_VERSION 0

#ifndef CIPE_DRIVER_MAJOR_VERSION
#   define CIPE_DRIVER_MAJOR_VERSION 2
#endif

#ifndef CIPE_DRIVER_MINOR_VERSION
#   define CIPE_DRIVER_MINOR_VERSION 1
#endif

#ifndef CIPE_MAC_ROOT_ADDRESS
#   define CIPE_MAC_ROOT_ADDRESS "8:0:58:0:0:1"
#endif

#define CIPE_CONTROL_CODE(request,method) CTL_CODE (FILE_DEVICE_PHYSICAL_NETCARD | 8000, request, method, FILE_ANY_ACCESS)

#define CIPE_IOCTL_GET_LASTMAC    CIPE_CONTROL_CODE (0, METHOD_BUFFERED)
#define CIPE_IOCTL_GET_MAC        CIPE_CONTROL_CODE (1, METHOD_BUFFERED)
#define CIPE_IOCTL_SET_STATISTICS CIPE_CONTROL_CODE (2, METHOD_BUFFERED)

/* Windows 2000 */
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

int setup_device(void)
{
	HKEY key, key2, adapterkey;
	int i;

	char adapterid[1024];
	char manufacturer[1024];
	char productname[1024];
	char adaptername[1024];
	char tapname[1024];
	char gelukt = 0;
	long len;

	FILETIME filetime;
	bool found = false;

	cp();

	get_config_string(lookup_config(config_tree, "Device"), &device);

	/* Open registry and look for network adapters */

	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, (OSTYPE > 4 ? NETCARD_REG_KEY_2000 : NETCARD_REG_KEY), 0, KEY_READ, &key)) {
		logger(LOG_ERR, _("Unable to read registry"));
		return -1;
	}

	for (i = 0; ; i++) {
		len = sizeof(adapterid);
		if(RegEnumKeyEx (key, i, adapterid, &len, 0, 0, 0, &filetime))
			break;

		/* Find out more about this adapter */

                if(RegOpenKeyEx (key, adapterid, 0, KEY_READ, &adapterkey)) {
			logger(LOG_ERR, _("Unable to read registry"));
			return -1;
		}

		len = sizeof(productname);
		if(RegQueryValueEx(adapterkey, "ProductName", 0, 0, productname, &len))
			goto skip;

		len = sizeof(manufacturer);
		if(RegQueryValueEx(adapterkey, "Manufacturer", 0, 0, manufacturer, &len))
			goto skip;

		if(!strcmp(productname, "CIPE") && !strcmp(manufacturer, "DKWHeavyIndustries")) {
			if(device && strcmp(adapterid, device))
				continue;
			if(!device)
				device = xstrdup(adapterid);
			found = true;
			break;
		}
		
skip:
                RegCloseKey (adapterkey);
	}

	if(!found) {
		logger(LOG_ERR, _("No CIPE adapters found!"));
		return -1;
	}

	/* Get adapter name */

	len = sizeof(adaptername);
	RegQueryValueEx(adapterkey, (OSTYPE > 4 ? "NetCfgInstanceId" : "ServiceName"), 0, 0, adaptername, &len);

	/* FIXME? cipsrvr checks if the device is in use at this point */

	/* Try to open the corresponding tap device */

	snprintf(tapname, sizeof(tapname), USERMODEDEVICEDIR "%s" TAPSUFFIX, adaptername);
	
	/* Now we are going to open this device twice: once for reading and once for writing.
	   We do this because apparently it isn't possible to check for activity in the select() loop.
	   Furthermore I don't really know how to do it the "Windows" way. */

	if(socketpair(AF_UNIX, SOCK_DGRAM, PF_UNIX, sp)) {
		logger(LOG_DEBUG, _("System call `%s' failed: %s"), "socketpair", strerror(errno));
		return -1;
	}

	reader_pid = fork();

	if(reader_pid == -1) {
		logger(LOG_DEBUG, _("System call `%s' failed: %s"), "fork", strerror(errno));
		return -1;
	}

	if(!reader_pid) {
		/* The child opens the tap device for reading, blocking.
		   It passes everything it reads to the socket. */
	
		char buf[MTU];
		int lenin;

		handle = CreateFile(tapname, GENERIC_READ,  FILE_SHARE_WRITE,  0,  OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM , 0);

		if(handle == INVALID_HANDLE_VALUE) {
			logger(LOG_ERR, _("Could not open CIPE tap device for reading!"));
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
			ReadFile (handle, buf, MTU, &lenin, NULL);
			write(sp[1], buf, lenin);
		}
	}

	/* The parent opens the tap device for writing. */
	
	handle = CreateFile(tapname, GENERIC_WRITE,  FILE_SHARE_READ,  0,  OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM , 0);
	
	if(handle == INVALID_HANDLE_VALUE) {
		logger(LOG_ERR, _("Could not open CIPE tap device for writing!"));
		return -1;
	}

	device_fd = sp[0];

	/* Get MAC address from tap device */

	if(routing_mode == RMODE_ROUTER) {
		DeviceIoControl (handle, CIPE_IOCTL_GET_MAC, mymac.x, sizeof(mymac.x), mymac.x, sizeof(mymac.x), &len, 0);
		overwrite_mac = 1;
	}

	read(device_fd, &gelukt, 1);
	if(gelukt != 1) {
		logger(LOG_DEBUG, "Tap reader failed!");
		return -1;
	}

	if(!get_config_string(lookup_config(config_tree, "Interface"), &iface))
		iface = device;

	device_info = _("Cygwin CIPE device");

	logger(LOG_INFO, _("%s is a %s"), device, device_info);

	return 0;
}

void close_device(void)
{
	cp();

	close(sp[0]);
	close(sp[1]);
	CloseHandle(handle);

	kill(reader_pid, SIGKILL);
}

int read_packet(vpn_packet_t *packet)
{
	int lenin;

	cp();

	if((lenin = read(sp[0], packet->data, MTU)) <= 0) {
		logger(LOG_ERR, _("Error while reading from %s %s: %s"), device_info,
			   device, strerror(errno));
		return -1;
	}
	
	packet->len = lenin;

	device_total_in += packet->len;

	ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Read packet of %d bytes from %s"), packet->len,
			   device_info);

	return 0;
}

int write_packet(vpn_packet_t *packet)
{
	int lenout;

	cp();

	ifdebug(TRAFFIC) logger(LOG_DEBUG, _("Writing packet of %d bytes to %s"),
			   packet->len, device_info);

	if(!WriteFile (handle, packet->data, packet->len, &lenout, NULL)) {
		logger(LOG_ERR, "Error while writing to %s %s", device_info, device);
		return -1;
	}

	device_total_out += packet->len;

	return 0;
}

void dump_device_stats(void)
{
	cp();

	logger(LOG_DEBUG, _("Statistics for %s %s:"), device_info, device);
	logger(LOG_DEBUG, _(" total bytes in:  %10d"), device_total_in);
	logger(LOG_DEBUG, _(" total bytes out: %10d"), device_total_out);
}
