/*
    device.c -- Interaction with Linux ethertap and tun/tap device
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

    $Id: device.c,v 1.1.2.8 2002/03/24 16:36:56 guus Exp $
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

#ifdef HAVE_TUNTAP
 #ifdef LINUX_IF_TUN_H
  #include LINUX_IF_TUN_H
 #else
  #include <linux/if_tun.h>
 #endif
 #define DEFAULT_DEVICE "/dev/misc/net/tun"
#else
 #define DEFAULT_DEVICE "/dev/tap0"
#endif

#include <utils.h>
#include "conf.h"
#include "net.h"
#include "subnet.h"

#include "system.h"

#define DEVICE_TYPE_ETHERTAP 0
#define DEVICE_TYPE_TUNTAP 1

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

cp
  if(!get_config_string(lookup_config(config_tree, "Device"), &device))
    device = DEFAULT_DEVICE;

  if(!get_config_string(lookup_config(config_tree, "Interface"), &interface))
#ifdef HAVE_TUNTAP
    interface = netname;
#else
    interface = rindex(device, '/')?rindex(device, '/')+1:device;
#endif
cp
  if((device_fd = open(device, O_RDWR | O_NONBLOCK)) < 0)
    {
      syslog(LOG_ERR, _("Could not open %s: %s"), device, strerror(errno));
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

#ifdef HAVE_TUNTAP
  /* Ok now check if this is an old ethertap or a new tun/tap thingie */

  memset(&ifr, 0, sizeof(ifr));
cp
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  if (interface)
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
cp
  if (!ioctl(device_fd, TUNSETIFF, (void *) &ifr))
  {
    device_info = _("Linux tun/tap device");
    device_type = DEVICE_TYPE_TUNTAP;
    strncpy(ifrname, ifr.ifr_name, IFNAMSIZ);
    interface = ifrname;
  }
  else
    if (!ioctl(device_fd, (('T'<< 8) | 202), (void *) &ifr))
    {
      syslog(LOG_WARNING, _("Old ioctl() request was needed for %s"), device);
      device_type = DEVICE_TYPE_TUNTAP;
      device_info = _("Linux tun/tap device");
      strncpy(ifrname, ifr.ifr_name, IFNAMSIZ);
      interface = ifrname;
    }
    else
#endif
    {
      device_info = _("Linux ethertap device");
      device_type = DEVICE_TYPE_ETHERTAP;
      interface = rindex(device, '/')?rindex(device, '/')+1:device;
    }

  syslog(LOG_INFO, _("%s is a %s"), device, device_info);
cp
  return 0;
}

void close_device(void)
{
cp
  close(device_fd);
}

/*
  read, encrypt and send data that is
  available through the ethertap device
*/
int read_packet(vpn_packet_t *packet)
{
  int lenin;
cp
  if(device_type == DEVICE_TYPE_TUNTAP)
    {
      if((lenin = read(device_fd, packet->data, MTU)) <= 0)
        {
          syslog(LOG_ERR, _("Error while reading from %s %s: %s"), device_info, device, strerror(errno));
          return -1;
        }

      packet->len = lenin;
    }
  else /* ethertap */
    {
      if((lenin = read(device_fd, packet->data - 2, MTU + 2)) <= 0)
        {
          syslog(LOG_ERR, _("Error while reading from %s %s: %s"), device_info, device, strerror(errno));
          return -1;
        }

      packet->len = lenin - 2;
    }

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

  if(device_type == DEVICE_TYPE_TUNTAP)
    {
      if(write(device_fd, packet->data, packet->len) < 0)
        {
          syslog(LOG_ERR, _("Can't write to %s %s: %s"), device_info, device, strerror(errno));
          return -1;
        }
    }
  else/* ethertap */
    {
      *(short int *)(packet->data - 2) = packet->len;
      if(write(device_fd, packet->data - 2, packet->len + 2) < 0)
        {
          syslog(LOG_ERR, _("Can't write to %s %s: %s"), device_info, device, strerror(errno));
          return -1;
        }
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
