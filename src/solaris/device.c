/*
    device.c -- Interaction with Solaris tun device
    Copyright (C) 2001 Ivo Timmermans <itimmermans@bigfoot.com>,
                  2001 Guus Sliepen <guus@sliepen.warande.net>

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

    $Id: device.c,v 1.1.2.2 2001/10/12 15:38:35 guus Exp $
*/

#include <sys/sockio.h>
#include <sys/stropts.h>
#include <net/if_tun.h>

#define DEFAULT_DEVICE "/dev/tun"

int device_fd = -1;
int device_type;
char *device_fname;
char *device_info;

int device_total_in = 0;
int device_total_out = 0;

int setup_device(void)
{
  int ip_fd = -1, if_fd = -1;
  int ppa;
  char *ptr;

cp
  if(!get_config_string(lookup_config(config_tree, "Device"), &device_fname)))
    device_fname = DEFAULT_DEVICE;

cp
  if((device_fd = open(device_fname, O_RDWR | O_NONBLOCK)) < 0)
    {
      syslog(LOG_ERR, _("Could not open %s: %m"), device_fname);
      return -1;
    }
cp
  ppa = 0;

  ptr = fname;
  while(*ptr && !isdigit((int)*ptr)) ptr++;
  ppa = atoi(ptr);

  if( (ip_fd = open("/dev/ip", O_RDWR, 0)) < 0){
     syslog(LOG_ERR, _("Could not open /dev/ip: %m"));
     return -1;
  }

  /* Assign a new PPA and get its unit number. */
  if( (ppa = ioctl(fd, TUNNEWPPA, ppa)) < 0){
     syslog(LOG_ERR, _("Can't assign new interface: %m"));
     return -1;
  }

  if( (if_fd = open(fname, O_RDWR, 0)) < 0){
     syslog(LOG_ERR, _("Could not open %s twice: %m"), fname);
     return -1;
  }

  if(ioctl(if_fd, I_PUSH, "ip") < 0){
     syslog(LOG_ERR, _("Can't push IP module: %m"));
     return -1;
  }

  /* Assign ppa according to the unit number returned by tun device */
  if(ioctl(if_fd, IF_UNITSEL, (char *)&ppa) < 0){
     syslog(LOG_ERR, _("Can't set PPA %d: %m"), ppa);
     return -1;
  }

  if(ioctl(ip_fd, I_LINK, if_fd) < 0){
     syslog(LOG_ERR, _("Can't link TUN device to IP: %m"));
     return -1;
  }

  device_info = _("Solaris tun device");

  /* Set default MAC address for ethertap devices */

  mymac.type = SUBNET_MAC;
  mymac.net.mac.address.x[0] = 0xfe;
  mymac.net.mac.address.x[1] = 0xfd;
  mymac.net.mac.address.x[2] = 0x00;
  mymac.net.mac.address.x[3] = 0x00;
  mymac.net.mac.address.x[4] = 0x00;
  mymac.net.mac.address.x[5] = 0x00;

  syslog(LOG_INFO, _("%s is a %s"), device_fname, device_info);
cp
  return 0;
}

int read_packet(vpn_packet_t *packet)
{
  int lenin;
cp
  if((lenin = read(device_fd, packet->data + 14, MTU - 14)) <= 0)
    {
      syslog(LOG_ERR, _("Error while reading from %s %s: %m"), device_info, device_fname);
      return -1;
    }

  memcpy(vp->data, mymac.net.mac.address.x, 6);
  memcpy(vp->data + 6, mymac.net.mac.address.x, 6);
  vp->data[12] = 0x08;
  vp->data[13] = 0x00;

  packet->len = lenin + 14;

  device_total_in += packet->len;

  if(debug_lvl >= DEBUG_TRAFFIC)
    {
      syslog(LOG_DEBUG, _("Read packet of %d bytes from %s"), device_info, packet.len);
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
      syslog(LOG_ERR, _("Can't write to %s %s: %m"), device_info, packet.len);
      return -1;
    }

  device_total_out += packet->len;
cp
}
