/*
    route.c -- routing
    Copyright (C) 2000,2001 Ivo Timmermans <itimmermans@bigfoot.com>,
                  2000,2001 Guus Sliepen <guus@sliepen.warande.net>

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

    $Id: route.c,v 1.1.2.8 2001/05/25 11:54:28 guus Exp $
*/

#include "config.h"

#include <netinet/in.h>
#include <utils.h>
#include <xalloc.h>
#include <syslog.h>

#include "net.h"
#include "connection.h"
#include "subnet.h"
#include "route.h"

#include "system.h"

int routing_mode = RMODE_ROUTER;
subnet_t mymac;

void learn_mac(connection_t *source, mac_t *address)
{
  subnet_t *subnet;
cp
  subnet = lookup_subnet_mac(address);
  
  if(!subnet)
    {
      subnet = new_subnet();
      subnet->type = SUBNET_MAC;
//      subnet->lasttime = gettimeofday();
      memcpy(&subnet->net.mac.address, address, sizeof(mac_t));
      subnet_add(source, subnet);

      if(debug_lvl >= DEBUG_TRAFFIC)
        {
          syslog(LOG_DEBUG, _("Learned new MAC address %x:%x:%x:%x:%x:%x from %s (%s)"),
               address->x[0],
               address->x[1],
               address->x[2],
               address->x[3],
               address->x[4],
               address->x[5],
               source->name, source->hostname);
        }
    }
}

connection_t *route_mac(connection_t *source, vpn_packet_t *packet)
{
  subnet_t *subnet;
cp
  /* Learn source address */

  learn_mac(source, (mac_t *)(&packet->data[0]));
  
  /* Lookup destination address */
    
  subnet = lookup_subnet_mac((mac_t *)(&packet->data[6]));

  if(!subnet)
    {
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
      return NULL;
    }
cp  
  return subnet->owner;  
}

connection_t *route_ipv4(vpn_packet_t *packet)
{
  ipv4_t dest;
  subnet_t *subnet;
cp
  dest = ntohl(*((unsigned long*)(&packet->data[30])));
  
  subnet = lookup_subnet_ipv4(&dest);

  if(!subnet)
    {
      if(debug_lvl >= DEBUG_TRAFFIC)
        {
          syslog(LOG_WARNING, _("Cannot route packet: unknown destination address %d.%d.%d.%d"),
                 packet->data[30], packet->data[31], packet->data[32], packet->data[33]);
        }

      return NULL;
    }
cp
  return subnet->owner;  
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
  avl_node_t *node;
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
         if(cl)
           send_packet(cl, packet);
         break;
        
      case RMODE_SWITCH:
        cl = route_mac(myself, packet);
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
      case RMODE_ROUTER:
        memcpy(packet->data, mymac.net.mac.address.x, 6);
        break;
      case RMODE_SWITCH:
        learn_mac(source, (mac_t *)(&packet->data[0]));
        break;
    }
  
  accept_packet(packet);
}
