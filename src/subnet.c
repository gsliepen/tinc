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

    $Id: subnet.c,v 1.1.2.8 2000/10/29 00:02:20 guus Exp $
*/

#include <syslog.h>
#include <stdio.h>

#include "config.h"
#include <utils.h>

#include <xalloc.h>
#include "subnet.h"
#include "net.h"
#include "conf.h"
#include "system.h"

/* lists type of subnet */

subnet_t *subnet_list[SUBNET_TYPES] = { NULL };

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
  subnet_t *p = NULL;
  subnet_t *q = NULL;
cp
  subnet->owner = cl;

  /* Link it into the owners list of subnets (unsorted) */

  subnet->next = cl->subnets;
  subnet->prev = NULL;
  if(subnet->next)
    subnet->next->prev = subnet;
  cl->subnets = subnet;
  
  /* And now add it to the global subnet list (sorted) */

  /* Sort on size of subnet mask (IPv4 only at the moment!)
  
     Three cases: subnet_list[] = NULL -> just add this subnet
                  insert before first -> add it in front of list
                  rest: insert after another subnet
   */
cp
  if(subnet_list[subnet->type])
    {
      p = q = subnet_list[subnet->type];

      for(; p; p = p->global_next)
        {
          if(subnet->net.ipv4.mask >= p->net.ipv4.mask)
            break;

          q = p;
        }
     }
cp  
  if(p == subnet_list[subnet->type])	/* First two cases */
    {
      /* Insert in front */
      subnet->global_next = subnet_list[subnet->type];
      subnet->global_prev = NULL;
      subnet_list[subnet->type] = subnet;
    }
  else                                  /* Third case */
    {
      /* Insert after q */
      subnet->global_next = q->global_next;
      subnet->global_prev = q;
      q->global_next = subnet;
    }
cp
  if(subnet->global_next)
    subnet->global_next->global_prev = subnet;
cp
}

void subnet_del(subnet_t *subnet)
{
cp
  /* Remove it from owner's list */

  if(subnet->prev)
    subnet->prev->next = subnet->next;
  else
    subnet->owner->subnets = subnet->next;

  if(subnet->next)
    subnet->next->prev = subnet->prev;

  /* Remove it from the global list */
  
  if(subnet->global_prev)
    subnet->global_prev->global_next = subnet->global_next;
  else
    subnet_list[subnet->type] = subnet->global_next;

  if(subnet->global_next)
    subnet->global_next->global_prev = subnet->global_prev;
  
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
  subnet_t *subnet;
cp
  for(subnet = subnet_list[SUBNET_MAC]; subnet != NULL; subnet = subnet->global_next)
    {
      if(memcmp(&address, &subnet->net.mac.address, sizeof(address)) == 0)
        break;
    }
cp
  return subnet;
}

subnet_t *lookup_subnet_ipv4(ipv4_t address)
{
  subnet_t *subnet;
cp
  for(subnet = subnet_list[SUBNET_IPV4]; subnet != NULL; subnet = subnet->global_next)
    {
      if((address & subnet->net.ipv4.mask) == subnet->net.ipv4.address)
        break;
    }
cp
  return subnet;
}

subnet_t *lookup_subnet_ipv6(ipv6_t address)
{
  subnet_t *subnet;
  int i;
cp
  for(subnet = subnet_list[SUBNET_IPV6]; subnet != NULL; subnet = subnet->global_next)
    {
      for(i=0; i<8; i++)
        if((address.x[i] & subnet->net.ipv6.mask.x[i]) != subnet->net.ipv6.address.x[i])
          break;
      if(i == 8)
        break;
    }
cp
  return subnet;
}

void dump_subnet_list(void)
{
  subnet_t *subnet;
  char *netstr;
cp
  syslog(LOG_DEBUG, _("Subnet list:"));

  for(subnet = subnet_list[SUBNET_IPV4]; subnet != NULL; subnet = subnet->global_next)
    {
      netstr = net2str(subnet);
      syslog(LOG_DEBUG, "  %s owner %s", netstr, subnet->owner->name);
      free(netstr);
    }

  syslog(LOG_DEBUG, _("End of subnet list."));
cp
}
