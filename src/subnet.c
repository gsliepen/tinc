/*
    subnet.c -- handle subnet lookups and lists
    Copyright (C) 2000 Guus Sliepen <guus@sliepen.warande.net>,
                  2000 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: subnet.c,v 1.1.2.12 2000/11/20 19:12:17 guus Exp $
*/

#include "config.h"

#include <stdio.h>
#include <syslog.h>

#include "conf.h"
#include "net.h"
#include "connection.h"
#include "subnet.h"
#include "system.h"

#include <utils.h>
#include <xalloc.h>
#include <rbl.h>

/* lists type of subnet */

rbltree_t _subnet_tree = { NULL };
rbltree_t *subnet_tree = &_subnet_tree;

/* Subnet comparison */

int subnet_compare_mac(subnet_t *a, subnet_t *b)
{
cp
  return memcmp(&a->net.mac.address, &b->net.mac.address, sizeof(mac_t));
}

int subnet_compare_ipv4(subnet_t *a, subnet_t *b)
{
cp
  /* If the subnet of a falls within the range of subnet b,
     then we consider a smaller then b.
     Otherwise, the addresses alone (and not the subnet masks) will be compared.
   */
   
  if(a->net.ipv4.mask > b->net.ipv4.mask)
    if((a->net.ipv4.address & b->net.ipv4.mask) == b->net.ipv4.address)
      return -1;

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
  rbl_insert(subnet_tree, subnet);
  rbl_insert(cl->subnet_tree, subnet);
cp
}

void subnet_del(subnet_t *subnet)
{
cp
  free_rbl(rbl_unlink(subnet->owner->subnet_tree, subnet));
  rbl_delete(subnet_tree, subnet);
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
        asprintf(&netstr, _("unknown"));
    }
cp
  return netstr;
}

/* Subnet lookup routines */

subnet_t *lookup_subnet_mac(mac_t address)
{
  subnet_t subnet;
cp
  subnet.type = SUBNET_MAC;
  subnet.net.mac.address = address;
  return (subnet_t *)rbl_search_closest(subnet_tree, &subnet);
}

subnet_t *lookup_subnet_ipv4(ipv4_t address)
{
  subnet_t subnet;
cp
  subnet.type = SUBNET_IPV4;
  subnet.net.ipv4.address = address;
  subnet.net.ipv4.mask = 0xFFFFFFFF;
  return (subnet_t *)rbl_search_closest(subnet_tree, &subnet);
}

subnet_t *lookup_subnet_ipv6(ipv6_t address)
{
  subnet_t subnet;
cp
  subnet.type = SUBNET_IPV6;
  subnet.net.ipv6.address = address;
  memset(&subnet.net.ipv6.mask, 0xFF, 16);
  return (subnet_t *)rbl_search_closest(subnet_tree, &subnet);
}

void dump_subnet_list(void)
{
  char *netstr;
  subnet_t *subnet;
  rbl_t *rbl;
cp
  syslog(LOG_DEBUG, _("Subnet list:"));
  RBL_FOREACH(subnet_tree, rbl)
    {
      subnet = (subnet_t *)rbl->data;
      netstr = net2str(subnet);
      syslog(LOG_DEBUG, " %s owner %s", netstr, subnet->owner->name);
      free(netstr);
    }
  syslog(LOG_DEBUG, _("End of subnet list."));
cp
}
