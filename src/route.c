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

    $Id: route.c,v 1.1.2.5 2001/01/07 15:25:49 guus Exp $
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

int routing_mode = RMODE_ROUTER;

void learn_mac(connection_t *source, mac_t *address)
{
  connection_t *old;
  subnet_t *subnet;
cp
  old = lookup_subnet_mac(address)->owner;
  
  if(!old)
    {
      subnet = new_subnet();
      subnet->type = SUBNET_MAC;
//      subnet->lasttime = gettimeofday();
      memcpy(&subnet->net.mac.address, address, sizeof(mac_t));
      subnet_add(source, subnet);

      if(DEBUG_LVL >= DEBUG_TRAFFIC)
        {
          syslog(LOG_DEBUG, _("Learned new MAC address %x:%x:%x:%x:%x:%x from %s (%s)"),
               address->address.x[0],
               address->address.x[1],
               address->address.x[2],
               address->address.x[3],
               address->address.x[4],
               address->address.x[5],
               cl->name, cl->hostname);
        }
    }
}

connection_t *route_mac(connection_t *source, vpn_packet_t *packet)
{
  connection_t *oldsrc, *dst;
  subnet_t *subnet;
cp
  /* Learn source address */

  learn_mac(source, (mac_t *)(&packet->data[0]));
  
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
      syslog(LOG_WARNING, _("Cannot route packet: IPv6 routing not yet implemented"));
    } 
cp
  return NULL;
}

void route_outgoing(vpn_packet_t *packet)
{
  unsigned short int type;
  avl_tree_t *node;
  connection_t *cl;
cp
  /* FIXME: multicast? */

  switch(routing_mode)
    {
      case RMODE_ROUTER:
        type = ntohs(*((unsigned short*)(&packet->data[12])));
        switch(type)
          {
            case 0x0800:
              cl = route_ipv4(packet);
              break;
            case 0x86DD:
              cl = route_ipv6(packet);
              break;
            default:
              if(debug_lvl >= DEBUG_TRAFFIC)
                {
                  syslog(LOG_WARNING, _("Cannot route packet: unknown type %hx"), type);
                }
              return;
           }
         send_packet(cl, packet);
         break;
        
      case RMODE_SWITCH:
        cl = route_mac(packet);
        if(cl)
          send_packet(cl, packet);
        break;
        
      case RMODE_HUB:
        for(node = connection_tree->head; node; node = node->next)
          {
            cl = (connection_t *)node->data;
            if(cl->status.active)
              send_packet(cl, packet);
          }
        break;
    }
}

void route_incoming(connection_t *source, vpn_packet_t *packet)
{
  switch(routing_mode)
    {
      case RMODE_SWITCH:
        learn_mac(source, &packet->data[0]);
        break;
    }
  
  accept_packet(packet);
}
