/*
    subnet.c -- handle subnet lookups and lists
    Copyright (C) 2000,2001 Guus Sliepen <guus@sliepen.warande.net>,
                  2000,2001 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: subnet.c,v 1.1.2.23 2001/06/29 13:09:55 guus Exp $
*/

#include "config.h"

#include <stdio.h>
#include <syslog.h>
#include <string.h>

#include "conf.h"
#include "net.h"
#include "connection.h"
#include "subnet.h"
#include "system.h"

#include <utils.h>
#include <xalloc.h>
#include <avl_tree.h>

/* lists type of subnet */

avl_tree_t *subnet_tree;

void init_subnets(void)
{
cp
  subnet_tree = avl_alloc_tree((avl_compare_t)subnet_compare, (avl_action_t)free_subnet);
cp
}

/* Subnet comparison */

int subnet_compare_mac(subnet_t *a, subnet_t *b)
{
cp
  return memcmp(&a->net.mac.address, &b->net.mac.address, sizeof(mac_t));
}

int subnet_compare_ipv4(subnet_t *a, subnet_t *b)
{
cp
  /* We compare as if a subnet is a number that equals (address << 32 + netmask). */
   
  if(a->net.ipv4.address == b->net.ipv4.address)
    return a->net.ipv4.mask - b->net.ipv4.mask;
  else
    return a->net.ipv4.address - b->net.ipv4.address;
}

int subnet_compare_ipv6(subnet_t *a, subnet_t *b)
{
cp
  /* Same as ipv4 case, but with nasty 128 bit addresses */
  
  if(memcmp(&a->net.ipv6.mask, &b->net.ipv6.mask, sizeof(ipv6_t)) > 0)
    if((a->net.ipv6.address.x[0] & b->net.ipv6.mask.x[0]) == b->net.ipv6.address.x[0] &&
       (a->net.ipv6.address.x[1] & b->net.ipv6.mask.x[1]) == b->net.ipv6.address.x[1] &&
       (a->net.ipv6.address.x[2] & b->net.ipv6.mask.x[2]) == b->net.ipv6.address.x[2] &&
       (a->net.ipv6.address.x[3] & b->net.ipv6.mask.x[3]) == b->net.ipv6.address.x[3] &&
       (a->net.ipv6.address.x[4] & b->net.ipv6.mask.x[4]) == b->net.ipv6.address.x[4] &&
       (a->net.ipv6.address.x[5] & b->net.ipv6.mask.x[5]) == b->net.ipv6.address.x[5] &&
       (a->net.ipv6.address.x[6] & b->net.ipv6.mask.x[6]) == b->net.ipv6.address.x[6] &&
       (a->net.ipv6.address.x[7] & b->net.ipv6.mask.x[7]) == b->net.ipv6.address.x[7])
      return -1;
  
  return memcmp(&a->net.ipv6.address, &b->net.ipv6.address, sizeof(ipv6_t));
}

int subnet_compare(subnet_t *a, subnet_t *b)
{
  int x;
cp  
  x = a->type - b->type;
  if(x)
    return x;
    
  switch(a->type)
    {
      case SUBNET_MAC:
        return subnet_compare_mac(a, b);
      case SUBNET_IPV4:
        return subnet_compare_ipv4(a, b);
      case SUBNET_IPV6:
        return subnet_compare_ipv6(a, b);
      default:
        syslog(LOG_ERR, _("subnet_compare() was called with unknown subnet type %d, restarting!"), a->type);
        sighup = 1;
        return 0;
    }
}

/* Allocating and freeing space for subnets */

subnet_t *new_subnet(void)
{
cp
  return (subnet_t *)xmalloc(sizeof(subnet_t));
}

void free_subnet(subnet_t *subnet)
{
cp
  free(subnet);
}

/* Linked list management */

void subnet_add(connection_t *cl, subnet_t *subnet)
{
cp
  subnet->owner = cl;

  while(!avl_insert(subnet_tree, subnet))
    {
      subnet_t *old;
      
      old = (subnet_t *)avl_search(subnet_tree, subnet);

      if(debug_lvl >= DEBUG_PROTOCOL)
        {
          char *subnetstr;
          subnetstr = net2str(subnet);
          syslog(LOG_WARNING, _("Duplicate subnet %s for %s (%s), previous owner %s (%s)!"),
                 subnetstr, cl->name, cl->hostname, old->owner->name, old->owner->hostname);
          free(subnetstr);
        }

      subnet_del(old);
    }

  avl_insert(cl->subnet_tree, subnet);
cp
}

void subnet_del(subnet_t *subnet)
{
cp
  avl_delete(subnet->owner->subnet_tree, subnet);
cp
  avl_delete(subnet_tree, subnet);
cp
}

/* Ascii representation of subnets */

subnet_t *str2net(char *subnetstr)
{
  int type;
  subnet_t *subnet;
cp
  if(sscanf(subnetstr, "%d,", &type) != 1)
    return NULL;
cp
  subnet = new_subnet();
cp
  switch(type)
    {
      case SUBNET_MAC:
        if(sscanf(subnetstr, "%d,%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &subnet->type,
                   &subnet->net.mac.address.x[0],
                   &subnet->net.mac.address.x[1],
                   &subnet->net.mac.address.x[2],
                   &subnet->net.mac.address.x[3],
                   &subnet->net.mac.address.x[4],
                   &subnet->net.mac.address.x[5]) != 7)
          {
            free_subnet(subnet);
            return NULL;
          }
        break;
      case SUBNET_IPV4:
        if(sscanf(subnetstr, "%d,%lx/%lx", &subnet->type, &subnet->net.ipv4.address, &subnet->net.ipv4.mask) != 3)
          {
            free_subnet(subnet);
            return NULL;
          }
        break;
      case SUBNET_IPV6:
        if(sscanf(subnetstr, "%d,%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx/%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx", &subnet->type,
                   &subnet->net.ipv6.address.x[0],
                   &subnet->net.ipv6.address.x[1],
                   &subnet->net.ipv6.address.x[2],
                   &subnet->net.ipv6.address.x[3],
                   &subnet->net.ipv6.address.x[4],
                   &subnet->net.ipv6.address.x[5],
                   &subnet->net.ipv6.address.x[6],
                   &subnet->net.ipv6.address.x[7],
                   &subnet->net.ipv6.mask.x[0],
                   &subnet->net.ipv6.mask.x[1],
                   &subnet->net.ipv6.mask.x[2],
                   &subnet->net.ipv6.mask.x[3],
                   &subnet->net.ipv6.mask.x[4],
                   &subnet->net.ipv6.mask.x[5],
                   &subnet->net.ipv6.mask.x[6],
                   &subnet->net.ipv6.mask.x[7]) != 17)
          {
            free_subnet(subnet);
            return NULL;
          }
        break;
      default:
        free_subnet(subnet);
        return NULL;
    }
cp
  return subnet;
}

char *net2str(subnet_t *subnet)
{
  char *netstr;
cp
  switch(subnet->type)
    {
      case SUBNET_MAC:
        asprintf(&netstr, "%d,%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", subnet->type,
                   subnet->net.mac.address.x[0],
                   subnet->net.mac.address.x[1],
                   subnet->net.mac.address.x[2],
                   subnet->net.mac.address.x[3],
                   subnet->net.mac.address.x[4],
                   subnet->net.mac.address.x[5]);
        break;
      case SUBNET_IPV4:
        asprintf(&netstr, "%d,%lx/%lx", subnet->type, subnet->net.ipv4.address, subnet->net.ipv4.mask);
        break;
      case SUBNET_IPV6:
        asprintf(&netstr, "%d,%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx/%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx", subnet->type,
                   subnet->net.ipv6.address.x[0],
                   subnet->net.ipv6.address.x[1],
                   subnet->net.ipv6.address.x[2],
                   subnet->net.ipv6.address.x[3],
                   subnet->net.ipv6.address.x[4],
                   subnet->net.ipv6.address.x[5],
                   subnet->net.ipv6.address.x[6],
                   subnet->net.ipv6.address.x[7],
                   subnet->net.ipv6.mask.x[0],
                   subnet->net.ipv6.mask.x[1],
                   subnet->net.ipv6.mask.x[2],
                   subnet->net.ipv6.mask.x[3],
                   subnet->net.ipv6.mask.x[4],
                   subnet->net.ipv6.mask.x[5],
                   subnet->net.ipv6.mask.x[6],
                   subnet->net.ipv6.mask.x[7]);
        break;
      default:
        asprintf(&netstr, _("unknown subnet type"));
    }
cp
  return netstr;
}

/* Subnet lookup routines */

subnet_t *lookup_subnet_mac(mac_t *address)
{
  subnet_t subnet, *p;
cp
  subnet.type = SUBNET_MAC;
  memcpy(&subnet.net.mac.address, address, sizeof(mac_t));

  p = (subnet_t *)avl_search(subnet_tree, &subnet);
cp
  return p;
}

subnet_t *lookup_subnet_ipv4(ipv4_t *address)
{
  subnet_t subnet, *p;
cp
  subnet.type = SUBNET_IPV4;
  subnet.net.ipv4.address = *address;
  subnet.net.ipv4.mask = 0xFFFFFFFF;

  do
  {
    /* Go find subnet */
  
    p = (subnet_t *)avl_search_closest_smaller(subnet_tree, &subnet);

  /* Check if the found subnet REALLY matches */
cp
    if(p)
      {
        if ((*address & p->net.ipv4.mask) == p->net.ipv4.address)
          break;
        else
          {
            /* Otherwise, see if there is a bigger enclosing subnet */

            subnet.net.ipv4.mask = p->net.ipv4.mask << 1;
            subnet.net.ipv4.address = p->net.ipv4.address & subnet.net.ipv4.mask;
          }
      }
   } while (p);
   
   return p;
}

subnet_t *lookup_subnet_ipv6(ipv6_t *address)
{
  subnet_t subnet, *p;
  int i;
cp
  subnet.type = SUBNET_IPV6;
  memcpy(&subnet.net.ipv6.address, address, sizeof(ipv6_t));
  memset(&subnet.net.ipv6.mask, 0xFF, 16);
  
  p = (subnet_t *)avl_search_closest_greater(subnet_tree, &subnet);
  
  if(p)
    for(i=0; i<8; i++)
      if((address->x[i] & p->net.ipv6.address.x[i]) != p->net.ipv6.address.x[i])
        return NULL;

  return p;
}

void dump_subnet_list(void)
{
  char *netstr;
  subnet_t *subnet;
  avl_node_t *node;
cp
  syslog(LOG_DEBUG, _("Subnet list:"));
  for(node = subnet_tree->head; node; node = node->next)
    {
      subnet = (subnet_t *)node->data;
      netstr = net2str(subnet);
      syslog(LOG_DEBUG, " %s owner %s", netstr, subnet->owner->name);
      free(netstr);
    }
  syslog(LOG_DEBUG, _("End of subnet list."));
cp
}
