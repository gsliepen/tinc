/*
    device.c -- raw socket
    Copyright (C) 2002 Ivo Timmermans <ivo@o2w.nl>,
                  2002 Guus Sliepen <guus@sliepen.eu.org>

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

    $Id: device.c,v 1.1.2.2 2002/09/09 21:25:28 guus Exp $
*/

#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#include <utils.h>
#include "conf.h"
#include "net.h"
#include "subnet.h"

#include "system.h"

int device_fd = -1;
int device_type;
char *device;
char *interface;
char ifrname[IFNAMSIZ];
char *device_info;

int device_total_in = 0;
int device_total_out = 0;

extern subnet_t mymac;

/*
  open the local ethertap device
*/
int setup_device(void)
{
	struct ifreq ifr;
	struct sockaddr_ll sa;
	cp if(!get_config_string
		  (lookup_config(config_tree, "Interface"), &interface))
		interface = "eth0";

	if(!get_config_string(lookup_config(config_tree, "Device"), &device))
		device = interface;

	device_info = _("raw socket");
	cp if((device_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		syslog(LOG_ERR, _("Could not open %s: %s"), device_info,
			   strerror(errno));
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_ifrn.ifrn_name, interface, IFNAMSIZ);
	if(ioctl(device_fd, SIOCGIFINDEX, &ifr)) {
		close(device_fd);
		syslog(LOG_ERR, _("Can't find interface %s: %s"), interface,
			   strerror(errno));
		return -1;
	}

	memset(&sa, '0', sizeof(sa));
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_ALL);
	sa.sll_ifindex = ifr.ifr_ifindex;

	if(bind(device_fd, (struct sockaddr *) &sa, (socklen_t) sizeof(sa))) {
		syslog(LOG_ERR, _("Could not bind to %s: %s"), device, strerror(errno));
		return -1;
	}
	cp
		/* Set default MAC address for ethertap devices */
		mymac.type = SUBNET_MAC;
	mymac.net.mac.address.x[0] = 0xfe;
	mymac.net.mac.address.x[1] = 0xfd;
	mymac.net.mac.address.x[2] = 0x00;
	mymac.net.mac.address.x[3] = 0x00;
	mymac.net.mac.address.x[4] = 0x00;
	mymac.net.mac.address.x[5] = 0x00;

	syslog(LOG_INFO, _("%s is a %s"), device, device_info);
	cp return 0;
}

void close_device(void)
{
	cp close(device_fd);
}

/*
  read, encrypt and send data that is
  available through the ethertap device
*/
int read_packet(vpn_packet_t * packet)
{
	int lenin;
	cp if((lenin = read(device_fd, packet->data, MTU)) <= 0) {
		syslog(LOG_ERR, _("Error while reading from %s %s: %s"), device_info,
			   device, strerror(errno));
		return -1;
	}

	packet->len = lenin;

	device_total_in += packet->len;

	if(debug_lvl >= DEBUG_TRAFFIC) {
		syslog(LOG_DEBUG, _("Read packet of %d bytes from %s"), packet->len,
			   device_info);
	}

	return 0;
cp}

int write_packet(vpn_packet_t * packet)
{
	cp if(debug_lvl >= DEBUG_TRAFFIC)
		syslog(LOG_DEBUG, _("Writing packet of %d bytes to %s"),
			   packet->len, device_info);

	if(write(device_fd, packet->data, packet->len) < 0) {
		syslog(LOG_ERR, _("Can't write to %s %s: %s"), device_info, device,
			   strerror(errno));
		return -1;
	}

	device_total_out += packet->len;
	cp return 0;
}

void dump_device_stats(void)
{
	cp syslog(LOG_DEBUG, _("Statistics for %s %s:"), device_info, device);
	syslog(LOG_DEBUG, _(" total bytes in:  %10d"), device_total_in);
	syslog(LOG_DEBUG, _(" total bytes out: %10d"), device_total_out);
cp}
