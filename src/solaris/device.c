/*
    device.c -- Interaction with Solaris tun device
    Copyright (C) 2001-2002 Ivo Timmermans <itimmermans@bigfoot.com>,
                  2001-2002 Guus Sliepen <guus@sliepen.warande.net>

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

    $Id: device.c,v 1.1.2.7 2002/02/18 16:25:19 guus Exp $
*/


#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stropts.h>
#include <sys/sockio.h>
#include <net/if_tun.h>

#define DEFAULT_DEVICE "/dev/tun"

#include <utils.h>
#include "conf.h"
#include "net.h"
#include "subnet.h"

#include "system.h"

int device_fd = -1;
int device_type;
char *device = NULL;
char *interface = NULL;
char ifrname[IFNAMSIZ];
char *device_info = NULL;

int device_total_in = 0;
int device_total_out = 0;

subnet_t mymac;

int setup_device(void)
{
  int ip_fd = -1, if_fd = -1;
  int ppa;
  char *ptr;

cp
  if(!get_config_string(lookup_config(config_tree, "Device"), &device))
    device = DEFAULT_DEVICE;

cp
  if((device_fd = open(device, O_RDWR | O_NONBLOCK)) < 0)
    {
      syslog(LOG_ERR, _("Could not open %s: %s"), device, strerror(errno));
      return -1;
    }
cp
  ppa = 0;

  ptr = device;
  while(*ptr && !isdigit((int)*ptr)) ptr++;
  ppa = atoi(ptr);

  if( (ip_fd = open("/dev/ip", O_RDWR, 0)) < 0){
     syslog(LOG_ERR, _("Could not open /dev/ip: %s"), strerror(errno));
     return -1;
  }

  /* Assign a new PPA and get its unit number. */
  if( (ppa = ioctl(device_fd, TUNNEWPPA, ppa)) < 0){
     syslog(LOG_ERR, _("Can't assign new interface: %s"), strerror(errno));
     return -1;
  }

  if( (if_fd = open(device, O_RDWR, 0)) < 0){
     syslog(LOG_ERR, _("Could not open %s twice: %s"), device, strerror(errno));
     return -1;
  }

  if(ioctl(if_fd, I_PUSH, "ip") < 0){
     syslog(LOG_ERR, _("Can't push IP module: %s"), strerror(errno));
     return -1;
  }

  /* Assign ppa according to the unit number returned by tun device */
  if(ioctl(if_fd, IF_UNITSEL, (char *)&ppa) < 0){
     syslog(LOG_ERR, _("Can't set PPA %d: %s"), ppa, strerror(errno));
     return -1;
  }

  if(ioctl(ip_fd, I_LINK, if_fd) < 0){
     syslog(LOG_ERR, _("Can't link TUN device to IP: %s"), strerror(errno));
     return -1;
  }

  if(!get_config_string(lookup_config(config_tree, "Interface"), &interface))
    asprintf(&interface, "tun%d", ppa);

  device_info = _("Solaris tun device");

  /* Set default MAC address for ethertap devices */

  mymac.type = SUBNET_MAC;
  mymac.net.mac.address.x[0] = 0xfe;
  mymac.net.mac.address.x[1] = 0xfd;
  mymac.net.mac.address.x[2] = 0x00;
  mymac.net.mac.address.x[3] = 0x00;
  mymac.net.mac.address.x[4] = 0x00;
  mymac.net.mac.address.x[5] = 0x00;

  syslog(LOG_INFO, _("%s is a %s"), device, device_info);
cp
  return 0;
}

void close_device(void)
{
cp
  close(device_fd);
}

int read_packet(vpn_packet_t *packet)
{
  int lenin;
cp
  if((lenin = read(device_fd, packet->data + 14, MTU - 14)) <= 0)
    {
      syslog(LOG_ERR, _("Error while reading from %s %s: %s"), device_info, device, strerror(errno));
      return -1;
    }

  memcpy(packet->data, mymac.net.mac.address.x, 6);
  memcpy(packet->data + 6, mymac.net.mac.address.x, 6);
  packet->data[12] = 0x08;
  packet->data[13] = 0x00;

  packet->len = lenin + 14;

  device_total_in += packet->len;

  if(debug_lvl >= DEBUG_TRAFFIC)
    {
      syslog(LOG_DEBUG, _("Read packet of %d bytes from %s"), packet->len, device_info);
    }

  return 0;
cp
}

int write_packet(vpn_packet_t *packet)
{
cp
  if(debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_DEBUG, _("Writing packet of %d bytes to %s"),
           packet->len, device_info);

  if(write(device_fd, packet->data + 14, packet->len - 14) < 0)
    {
      syslog(LOG_ERR, _("Can't write to %s %s: %s"), device_info, packet->len, strerror(errno));
      return -1;
    }

  device_total_out += packet->len;
cp
  return 0;
}

void dump_device_stats(void)
{
cp
  syslog(LOG_DEBUG, _("Statistics for %s %s:"), device_info, device);
  syslog(LOG_DEBUG, _(" total bytes in:  %10d"), device_total_in);
  syslog(LOG_DEBUG, _(" total bytes out: %10d"), device_total_out);
cp
}
