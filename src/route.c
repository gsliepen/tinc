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

    $Id: route.c,v 1.1.2.16 2001/07/20 13:54:19 guus Exp $
*/

#include "config.h"

#ifdef HAVE_FREEBSD
 #include <sys/param.h>
#endif
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef HAVE_SOLARIS
 #include <netinet/if.h>
 #define ETHER_ADDR_LEN 6
#else
 #include <net/ethernet.h>
#endif
#include <netinet/if_ether.h>
#include <utils.h>
#include <xalloc.h>
#include <syslog.h>
#include <string.h>

#include <avl_tree.h>

#include "net.h"
#include "connection.h"
#include "subnet.h"
#include "route.h"
#include "protocol.h"

#include "system.h"

int routing_mode = RMODE_ROUTER;
subnet_t mymac;

void learn_mac(mac_t *address)
{
  subnet_t *subnet;
  avl_node_t *node;
  connection_t *p;
cp
  subnet = lookup_subnet_mac(address);

  /* If we don't know this MAC address yet, store it */
  
  if(!subnet || subnet->owner!=myself)
    {
      if(debug_lvl >= DEBUG_TRAFFIC)
        syslog(LOG_INFO, _("Learned new MAC address %hhx:%hhx:%hhx:%hhx:%hhx:%hhx"),
               address->x[0], address->x[1], address->x[2], address->x[3],  address->x[4], address->x[5]);
               
      subnet = new_subnet();
      subnet->type = SUBNET_MAC;
      memcpy(&subnet->net.mac.address, address, sizeof(mac_t));
      subnet_add(myself, subnet);

      /* And tell all other tinc daemons it's our MAC */
      
      for(node = connection_tree->head; node; node = node->next)
        {
          p = (connection_t *)node->data;
          if(p->status.active && p!= myself)
            send_add_subnet(p, subnet);
        }
    }
}

connection_t *route_mac(vpn_packet_t *packet)
{
  subnet_t *subnet;
cp
  /* Learn source address */

  learn_mac((mac_t *)(&packet->data[6]));
  
  /* Lookup destination address */
    
  subnet = lookup_subnet_mac((mac_t *)(&packet->data[0]));

  if(subnet)
    return subnet->owner;
  else
    return NULL;
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

void route_arp(vpn_packet_t *packet)
{
  struct ether_arp *arp;
  subnet_t *subnet;
  unsigned char ipbuf[4];
  ipv4_t dest;
cp
  /* First, snatch the source address from the ARP packet */

  memcpy(mymac.net.mac.address.x, packet->data + 6, 6);

  /* This routine generates replies to ARP requests.
     You don't need to set NOARP flag on the interface anymore (which is broken on FreeBSD).
     Most of the code here is taken from choparp.c by Takamichi Tateoka (tree@mma.club.uec.ac.jp)
   */

  arp = (struct ether_arp *)(packet->data + 14);

  /* Check if this is a valid ARP request */

  if(ntohs(arp->arp_hrd) != ARPHRD_ETHER ||
     ntohs(arp->arp_pro) != ETHERTYPE_IP ||
     (int) (arp->arp_hln) != ETHER_ADDR_LEN ||
     (int) (arp->arp_pln) != 4 ||
     ntohs(arp->arp_op) != ARPOP_REQUEST )
    {
      if(debug_lvl > DEBUG_TRAFFIC)
        {
          syslog(LOG_WARNING, _("Cannot route packet: received unknown type ARP request"));
        } 
      return;
    }

  /* Check if the IP address exists on the VPN */

  dest = ntohl(*((unsigned long*)(arp->arp_tpa)));
  subnet = lookup_subnet_ipv4(&dest);

  if(!subnet)
    {
      if(debug_lvl >= DEBUG_TRAFFIC)
        {
          syslog(LOG_WARNING, _("Cannot route packet: ARP request for unknown address %d.%d.%d.%d"),
                 arp->arp_tpa[0], arp->arp_tpa[1], arp->arp_tpa[2], arp->arp_tpa[3]);
        }

      return;
    }

  /* Check if it is for our own subnet */
  
  if(subnet->owner == myself)
    return;	/* silently ignore */

  memcpy(packet->data, packet->data + ETHER_ADDR_LEN, ETHER_ADDR_LEN);	/* copy destination address */
  packet->data[ETHER_ADDR_LEN*2 - 1] ^= 0xFF;				/* mangle source address so it looks like it's not from us */

  memcpy(ipbuf, arp->arp_tpa, 4);					/* save protocol addr */
  memcpy(arp->arp_tpa, arp->arp_spa, 4);				/* swap destination and source protocol address */
  memcpy(arp->arp_spa, ipbuf, 4);					/* ... */

  memcpy(arp->arp_tha, arp->arp_sha, 10);				/* set target hard/proto addr */
  memcpy(arp->arp_sha, packet->data + ETHER_ADDR_LEN, ETHER_ADDR_LEN);	/* add fake source hard addr */
  arp->arp_op = htons(ARPOP_REPLY);
  
  accept_packet(packet);
cp
}

void route_outgoing(vpn_packet_t *packet)
{
  unsigned short int type;
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
            case 0x0806:
              route_arp(packet);
              return;
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
        cl = route_mac(packet);
        if(cl)
          send_packet(cl, packet);
        else
          broadcast_packet(myself, packet);
        break;
        
      case RMODE_HUB:
        broadcast_packet(myself, packet);
        break;
    }
}

void route_incoming(connection_t *source, vpn_packet_t *packet)
{
  switch(routing_mode)
    {
      case RMODE_ROUTER:
        memcpy(packet->data, mymac.net.mac.address.x, 6);	/* Override destination address to make the kernel accept it */
        accept_packet(packet);
        break;
      case RMODE_SWITCH:
        {
          subnet_t *subnet;

          subnet = lookup_subnet_mac((mac_t *)(&packet->data[0]));

          if(subnet)
            {
              if(subnet->owner == myself)
                accept_packet(packet);
              else
                send_packet(subnet->owner, packet);
            }
          else
            {
              broadcast_packet(source, packet);
              accept_packet(packet);
            }
          }
        break;
      case RMODE_HUB:
        broadcast_packet(source,packet);			/* Spread it on */
        accept_packet(packet);
        break;
    }
}
