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

    $Id: subnet.c,v 1.1.2.4 2000/10/15 00:59:37 guus Exp $
*/

#include "config.h"
#include <utils.h>

#include <xalloc.h>
#include "subnet.h"
#include "net.h"

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

void subnet_add(conn_list_t *cl, subnet_t *subnet)
{
cp
  /* FIXME: do sorting on netmask size if necessary */

  subnet->next = cl->subnets->next;
  subnet->prev = NULL;
  subnet->next->prev = subnet;
  cl->subnets = subnet;
cp
}

void subnet_del(subnet_t *subnet)
{
cp
  if(subnet->prev)
    {
      subnet->prev->next = subnet->next;
    }
  else
    {
      subnet->owner->subnets = subnet->next;
    }

  subnet->next->prev = subnet->prev;
  free_subnet(subnet);
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

  subnet = new_subnet();

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
        if(sscanf(subnetstr, "%d,%lx:%lx", &subnet->type, &subnet->net.ipv4.address, &subnet->net.ipv4.mask) != 3)
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
      case SUBNET_IPV4:
        asprintf(&netstr, "%d,%lx:%lx", subnet->type, subnet->net.ipv4.address, subnet->net.ipv4.mask);
      case SUBNET_IPV6:
        asprintf(&netstr, "%d,%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx/%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx",
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
      default:
        netstr = NULL;
    }
cp
  return netstr;
}

/* Subnet lookup routines */

subnet_t *lookup_subnet_mac(subnet_t *subnets, mac_t address)
{
  subnet_t *subnet;
cp
  for(subnet = subnets; subnet != NULL; subnet = subnet->next)
    {
      if(subnet->type == SUBNET_MAC)
        if(memcmp(&address, &subnet->net.mac.address, sizeof(address)) == 0)
          break;
    }
cp
  return subnet;
}

subnet_t *lookup_subnet_ipv4(subnet_t *subnets, ipv4_t address)
{
  subnet_t *subnet;
cp
  for(subnet = subnets; subnet != NULL; subnet = subnet->next)
    {
      if(subnet->type == SUBNET_IPV4)
        if((address & subnet->net.ipv4.mask) == subnet->net.ipv4.address)
          break;
    }
cp
  return subnet;
}

subnet_t *lookup_subnet_ipv6(subnet_t *subnets, ipv6_t address)
{
  subnet_t *subnet;
  int i;
cp
  for(subnet = subnets; subnet != NULL; subnet = subnet->next)
    {
      if(subnet->type == SUBNET_IPV6)
        {
          for(i=0; i<8; i++)
            if((address.x[i] & subnet->net.ipv6.mask.x[i]) != subnet->net.ipv6.address.x[i])
              break;
          if(i=8)
            break;
        }
    }
cp
  return subnet;
}
