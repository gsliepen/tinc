/*
    route.c -- routing
    Copyright (C) 2000 Ivo Timmermans <itimmermans@bigfoot.com>,
                  2000 Guus Sliepen <guus@sliepen.warande.net>

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

    $Id: route.c,v 1.1.2.4 2001/01/05 23:53:53 guus Exp $
*/

#include "config.h"

#include <utils.h>
#include <xalloc.h>
#include <syslog.h>

#include "net.h"
#include "connection.h"
#include "subnet.h"
#include "route.h"

#include "system.h"

int routing_mode = RMODE_ROUTER;	/* Will be used to determine if we route by MAC or by payload's protocol */

connection_t *route_mac(connection_t *source, vpn_packet_t *packet)
{
  connection_t *oldsrc, *dst;
  subnet_t *subnet;
cp
  /* Learn source address */

  oldsrc = lookup_subnet_mac((mac_t *)(&packet->data[0]))->owner;
  
  if(!oldsrc)
    {
      subnet = new_subnet();
      subnet->type = SUBNET_MAC;
      memcpy(&subnet->net.mac.address, (mac_t *)(&packet->data[0]), sizeof(mac_t));
      subnet_add(source, subnet);
    }

  /* FIXME: do ageing and roaming */
  
  /* Lookup destination address */
    
  dst = lookup_subnet_mac((mac_t *)(&packet->data[6]))->owner;

  if(!dst)
    if(debug_lvl >= DEBUG_TRAFFIC)
      {
        syslog(LOG_WARNING, _("Cannot route packet: unknown destination address %x:%x:%x:%x:%x:%x"),
               packet->data[6],
               packet->data[7],
               packet->data[8],
               packet->data[9],
               packet->data[10],
               packet->data[11]);
      } 
cp  
  return dst;  
}

connection_t *route_ipv4(vpn_packet_t *packet)
{
  ipv4_t dest;
  connection_t *cl;
cp
  dest = ntohl(*((unsigned long*)(&packet->data[30])));
  
  cl = lookup_subnet_ipv4(&dest)->owner;
  if(!cl)
    if(debug_lvl >= DEBUG_TRAFFIC)
      {
        syslog(LOG_WARNING, _("Cannot route packet: unknown destination address %d.%d.%d.%d"),
               packet->data[30], packet->data[31], packet->data[32], packet->data[33]);
      } 
cp
  return cl;  
}

connection_t *route_ipv6(vpn_packet_t *packet)
{
cp
  if(debug_lvl > DEBUG_NOTHING)
    {
      syslog(LOG_WARNING, _("Cannot route packet: IPv6 routing not implemented yet"));
    } 
cp
  return NULL;
}

connection_t *route_packet(connection_t *source, vpn_packet_t *packet)
{
  unsigned short int type;
cp
  /* FIXME: multicast? */

  switch(routing_mode)
    {
      case RMODE_HUB:
        return broadcast;
        
      case RMODE_SWITCH:
        return route_mac(source, packet);
        
      case RMODE_ROUTER:
        type = ntohs(*((unsigned short*)(&packet->data[12])));
        switch(type)
          {
            case 0x0800:
              return route_ipv4(packet);
            case 0x86DD:
              return route_ipv6(packet);
      /*
            case 0x8137:
              return route_ipx(packet);
            case 0x0806:
              return route_arp(packet);
      */
            default:
              if(debug_lvl >= DEBUG_TRAFFIC)
                {
                  syslog(LOG_WARNING, _("Cannot route packet: unknown type %hx"), type);
                }
              return NULL;
           }
    }
}
