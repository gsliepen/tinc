/*
    subnet.c -- handle subnet lookups and lists
    Copyright (C) 2000-2002 Guus Sliepen <guus@sliepen.warande.net>,
                  2000-2002 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: subnet.c,v 1.1.2.34 2002/04/09 11:42:48 guus Exp $
*/

#include "config.h"

#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>

#include <utils.h>
#include <xalloc.h>
#include <avl_tree.h>

#include "conf.h"
#include "net.h"
#include "node.h"
#include "subnet.h"
#include "netutl.h"

#include "system.h"

/* lists type of subnet */

avl_tree_t *subnet_tree;

/* Subnet comparison */

int subnet_compare_mac(subnet_t *a, subnet_t *b)
{
cp
  return memcmp(&a->net.mac.address, &b->net.mac.address, sizeof(mac_t));
}

int subnet_compare_ipv4(subnet_t *a, subnet_t *b)
{
  int result;
cp
  result = memcmp(&a->net.ipv4.address, &b->net.ipv4.address, sizeof(ipv4_t));
  
  if(result)
    return result;

  return a->net.ipv4.prefixlength - b->net.ipv4.prefixlength;
}

int subnet_compare_ipv6(subnet_t *a, subnet_t *b)
{
  int result;
cp
  result = memcmp(&a->net.ipv6.address, &b->net.ipv6.address, sizeof(ipv6_t));
  
  if(result)
    return result;

  return a->net.ipv6.prefixlength - b->net.ipv6.prefixlength;
}

int subnet_compare(subnet_t *a, subnet_t *b)
{
  int result;
cp  
  result = a->type - b->type;
 
  if(result)
    return result;
    
  switch(a->type)
    {
      case SUBNET_MAC:
        return subnet_compare_mac(a, b);
      case SUBNET_IPV4:
        return subnet_compare_ipv4(a, b);
      case SUBNET_IPV6:
        return subnet_compare_ipv6(a, b);
      default:
        syslog(LOG_ERR, _("subnet_compare() was called with unknown subnet type %d, exitting!"), a->type);
        cp_trace();
        exit(0);
    }

  return 0;
}

/* Initialising trees */

void init_subnets(void)
{
cp
  subnet_tree = avl_alloc_tree((avl_compare_t)subnet_compare, (avl_action_t)free_subnet);
cp
}

void exit_subnets(void)
{
cp
  avl_delete_tree(subnet_tree);
cp
}

avl_tree_t *new_subnet_tree(void)
{
cp
  return avl_alloc_tree((avl_compare_t)subnet_compare, NULL);
cp
}

void free_subnet_tree(avl_tree_t *subnet_tree)
{
cp
  avl_delete_tree(subnet_tree);
cp
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

/* Adding and removing subnets */

void subnet_add(node_t *n, subnet_t *subnet)
{
cp
  subnet->owner = n;

  avl_insert(subnet_tree, subnet);
cp
  avl_insert(n->subnet_tree, subnet);
cp
}

void subnet_del(node_t *n, subnet_t *subnet)
{
cp
  avl_delete(n->subnet_tree, subnet);
cp
  avl_delete(subnet_tree, subnet);
cp
}

/* Ascii representation of subnets */

subnet_t *str2net(char *subnetstr)
{
  int i, l;
  subnet_t *subnet;
  unsigned short int x[8];
cp
  subnet = new_subnet();
cp
  if(sscanf(subnetstr, "%hu.%hu.%hu.%hu/%d",
              &x[0], &x[1], &x[2], &x[3],
              &l) == 5)
    {
      subnet->type = SUBNET_IPV4;
      subnet->net.ipv4.prefixlength = l;
      for(i = 0; i < 4; i++)
        subnet->net.ipv4.address.x[i] = x[i];
      return subnet;
    }
	      
  if(sscanf(subnetstr, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx/%d",
             &x[0], &x[1], &x[2], &x[3], &x[4], &x[5], &x[6], &x[7],
             &l) == 9)
    {
      subnet->type = SUBNET_IPV6;
      subnet->net.ipv6.prefixlength = l;
      for(i = 0; i < 8; i++)
        subnet->net.ipv6.address.x[i] = htons(x[i]);
      return subnet;
    }

  if(sscanf(subnetstr, "%hu.%hu.%hu.%hu",
              &x[0], &x[1], &x[2], &x[3]) == 4)
    {
      subnet->type = SUBNET_IPV4;
      subnet->net.ipv4.prefixlength = 32;
      for(i = 0; i < 4; i++)
        subnet->net.ipv4.address.x[i] = x[i];
      return subnet;
    }
	      
  if(sscanf(subnetstr, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx",
             &x[0], &x[1], &x[2], &x[3], &x[4], &x[5], &x[6], &x[7]) == 8)
    {
      subnet->type = SUBNET_IPV6;
      subnet->net.ipv6.prefixlength = 128;
      for(i = 0; i < 8; i++)
        subnet->net.ipv6.address.x[i] = htons(x[i]);
      return subnet;
    }

  if(sscanf(subnetstr, "%hx:%hx:%hx:%hx:%hx:%hx",
              &x[0], &x[1], &x[2], &x[3], &x[4], &x[5]) == 6)
    {
      subnet->type = SUBNET_MAC;
      for(i = 0; i < 6; i++)
        subnet->net.mac.address.x[i] = x[i];
      return subnet;
    }

  free(subnet);
  return NULL;
}

char *net2str(subnet_t *subnet)
{
  char *netstr;
cp
  switch(subnet->type)
    {
      case SUBNET_MAC:
        asprintf(&netstr, "%hx:%hx:%hx:%hx:%hx:%hx",
                   subnet->net.mac.address.x[0],
                   subnet->net.mac.address.x[1],
                   subnet->net.mac.address.x[2],
                   subnet->net.mac.address.x[3],
                   subnet->net.mac.address.x[4],
                   subnet->net.mac.address.x[5]);
        break;
      case SUBNET_IPV4:
        asprintf(&netstr, "%hu.%hu.%hu.%hu/%d",
	           subnet->net.ipv4.address.x[0],
	           subnet->net.ipv4.address.x[1],
	           subnet->net.ipv4.address.x[2],
	           subnet->net.ipv4.address.x[3],
		   subnet->net.ipv4.prefixlength);
        break;
      case SUBNET_IPV6:
        asprintf(&netstr, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx/%d",
                   ntohs(subnet->net.ipv6.address.x[0]),
                   ntohs(subnet->net.ipv6.address.x[1]),
                   ntohs(subnet->net.ipv6.address.x[2]),
                   ntohs(subnet->net.ipv6.address.x[3]),
                   ntohs(subnet->net.ipv6.address.x[4]),
                   ntohs(subnet->net.ipv6.address.x[5]),
                   ntohs(subnet->net.ipv6.address.x[6]),
                   ntohs(subnet->net.ipv6.address.x[7]),
                   subnet->net.ipv6.prefixlength);
        break;
      default:
        syslog(LOG_ERR, _("net2str() was called with unknown subnet type %d, exitting!"), subnet->type);
	cp_trace();
        exit(0);
    }
cp
  return netstr;
}

/* Subnet lookup routines */

subnet_t *lookup_subnet(node_t *owner, subnet_t *subnet)
{
cp  
  return avl_search(owner->subnet_tree, subnet);
}

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
  memcpy(&subnet.net.ipv4.address, address, sizeof(ipv4_t));
  subnet.net.ipv4.prefixlength = 32;

  do
  {
    /* Go find subnet */
  
    p = (subnet_t *)avl_search_closest_smaller(subnet_tree, &subnet);

  /* Check if the found subnet REALLY matches */
cp
    if(p)
      {
	if(p->type != SUBNET_IPV4)
	  {
	    p = NULL;
	    break;
	  }

        if (!maskcmp((char *)address, (char *)&p->net.ipv4.address, p->net.ipv4.prefixlength, sizeof(ipv4_t)))
          break;
        else
          {
            /* Otherwise, see if there is a bigger enclosing subnet */

            subnet.net.ipv4.prefixlength = p->net.ipv4.prefixlength - 1;
            maskcpy((char *)&subnet.net.ipv4.address, (char *)&p->net.ipv4.address, subnet.net.ipv4.prefixlength, sizeof(ipv4_t));
          }
      }
  } while (p);
cp
  return p;
}

subnet_t *lookup_subnet_ipv6(ipv6_t *address)
{
  subnet_t subnet, *p;
cp
  subnet.type = SUBNET_IPV6;
  memcpy(&subnet.net.ipv6.address, address, sizeof(ipv6_t));
  subnet.net.ipv6.prefixlength = 128;
  
  do
  {
    /* Go find subnet */
  
    p = (subnet_t *)avl_search_closest_smaller(subnet_tree, &subnet);

    /* Check if the found subnet REALLY matches */

cp
    if(p)
      {
	if(p->type != SUBNET_IPV6)
	  return NULL;

        if (!maskcmp((char *)address, (char *)&p->net.ipv6.address, p->net.ipv6.prefixlength, sizeof(ipv6_t)))
          break;
        else
          {
            /* Otherwise, see if there is a bigger enclosing subnet */

            subnet.net.ipv6.prefixlength = p->net.ipv6.prefixlength - 1;
            maskcpy((char *)&subnet.net.ipv6.address, (char *)&p->net.ipv6.address, subnet.net.ipv6.prefixlength, sizeof(ipv6_t));
          }
      }
   } while (p);
cp   
  return p;
}

void dump_subnets(void)
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
      syslog(LOG_DEBUG, _(" %s owner %s"), netstr, subnet->owner->name);
      free(netstr);
    }
  syslog(LOG_DEBUG, _("End of subnet list."));
cp
}
