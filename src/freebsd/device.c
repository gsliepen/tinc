/*
    device.c -- Interaction with FreeBSD tap device
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

    $Id: device.c,v 1.1.2.1 2001/10/12 15:22:59 guus Exp $
*/

#define DEFAULT_DEVICE "/dev/tap0"

int device_fd = -1;
int device_type;
char *device_fname;
char *device_info;

int device_total_in = 0;
int device_total_out = 0;

*
  open the local ethertap device
*/
int setup_device(void)
{
  struct ifreq ifr;

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
  device_fd = device_fd;

  /* Set default MAC address for ethertap devices */

  mymac.type = SUBNET_MAC;
  mymac.net.mac.address.x[0] = 0xfe;
  mymac.net.mac.address.x[1] = 0xfd;
  mymac.net.mac.address.x[2] = 0x00;
  mymac.net.mac.address.x[3] = 0x00;
  mymac.net.mac.address.x[4] = 0x00;
  mymac.net.mac.address.x[5] = 0x00;

  device_info = _("FreeBSD tap device");

  syslog(LOG_INFO, _("%s is a %s"), device_fname, device_info);
cp
  return 0;
}

/*
  read, encrypt and send data that is
  available through the ethertap device
*/
int read_packet(vpn_packet_t *packet)
{
  int lenin;
cp
  if((lenin = read(device_fd, packet->data, MTU)) <= 0)
    {
      syslog(LOG_ERR, _("Error while reading from %s %s: %m"), device_info, device_fname);
      return -1;
    }

  packet->len = lenin;

  device_total_in += packet->len;

  if(debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_DEBUG, _("Read packet of %d bytes from %s"),
           packet->len, device_info);

  return 0;
cp
}

int write_packet(vpn_packet_t *packet)
{
cp
  if(debug_lvl >= DEBUG_TRAFFIC)
    syslog(LOG_DEBUG, _("Writing packet of %d bytes to %s"),
           packet->len, device_info);

  if(write(device_fd, packet->data, packet->len) < 0)
    {
      syslog(LOG_ERR, _("Error while writing to %s %s: %m"), device_info, device_fname);
      return -1;
    }

  device_total_out += packet->len;
cp
}
