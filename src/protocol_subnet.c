/*
    protocol_subnet.c -- handle the meta-protocol, subnets
    Copyright (C) 1999-2002 Ivo Timmermans <itimmermans@bigfoot.com>,
                  2000-2002 Guus Sliepen <guus@sliepen.warande.net>

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

    $Id: protocol_subnet.c,v 1.1.4.3 2002/03/22 13:31:18 guus Exp $
*/

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#include <utils.h>
#include <xalloc.h>
#include <avl_tree.h>

#include "conf.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "meta.h"
#include "connection.h"
#include "node.h"
#include "edge.h"
#include "graph.h"

#include "system.h"

int send_add_subnet(connection_t *c, subnet_t *subnet)
{
  int x;
  char *netstr;
cp
  x = send_request(c, "%d %lx %s %s", ADD_SUBNET, random(),
                      subnet->owner->name, netstr = net2str(subnet));
  free(netstr);
cp
  return x;
}

int add_subnet_h(connection_t *c)
{
  char subnetstr[MAX_STRING_SIZE];
  char name[MAX_STRING_SIZE];
  node_t *owner;
  connection_t *other;
  subnet_t *s;
  avl_node_t *node;
cp
  if(sscanf(c->buffer, "%*d %*x "MAX_STRING" "MAX_STRING, name, subnetstr) != 2)
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "ADD_SUBNET", c->name, c->hostname);
      return -1;
    }

  /* Check if owner name is a valid */

  if(check_id(name))
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "ADD_SUBNET", c->name, c->hostname, _("invalid name"));
      return -1;
    }

  /* Check if subnet string is valid */

  if(!(s = str2net(subnetstr)))
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "ADD_SUBNET", c->name, c->hostname, _("invalid subnet string"));
      return -1;
    }

  if(seen_request(c->buffer))
    return 0;
 
  /* Check if the owner of the new subnet is in the connection list */

  owner = lookup_node(name);

  if(!owner)
    {
      owner = new_node();
      owner->name = xstrdup(name);
      node_add(owner);
    }

  /* Check if we already know this subnet */
  
  if(lookup_subnet(owner, s))
    {
      free_subnet(s);
      return 0;
    }

  /* If we don't know this subnet, but we are the owner, retaliate with a DEL_SUBNET */

  if(owner == myself)
  {
    if(debug_lvl >= DEBUG_PROTOCOL)
      syslog(LOG_WARNING, _("Got %s from %s (%s) for ourself"), "ADD_SUBNET", c->name, c->hostname);
    s->owner = myself;
    send_del_subnet(c, s);
    return 0;
  }

  /* If everything is correct, add the subnet to the list of the owner */

  subnet_add(owner, s);

  /* Tell the rest */
  
  for(node = connection_tree->head; node; node = node->next)
    {
      other = (connection_t *)node->data;
      if(other->status.active && other != c)
        send_request(other, "%s", c->buffer);
    }
cp
  return 0;
}

int send_del_subnet(connection_t *c, subnet_t *s)
{
  int x;
  char *netstr;
cp
  netstr = net2str(s);
  x = send_request(c, "%d %lx %s %s", DEL_SUBNET, random(), s->owner->name, netstr);
  free(netstr);
cp
  return x;
}

int del_subnet_h(connection_t *c)
{
  char subnetstr[MAX_STRING_SIZE];
  char name[MAX_STRING_SIZE];
  node_t *owner;
  connection_t *other;
  subnet_t *s, *find;
  avl_node_t *node;
cp
  if(sscanf(c->buffer, "%*d %*x "MAX_STRING" "MAX_STRING, name, subnetstr) != 2)
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "DEL_SUBNET", c->name, c->hostname);
      return -1;
    }

  /* Check if owner name is a valid */

  if(check_id(name))
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "DEL_SUBNET", c->name, c->hostname, _("invalid name"));
      return -1;
    }

  /* Check if the owner of the new subnet is in the connection list */

  if(!(owner = lookup_node(name)))
    {
      if(debug_lvl >= DEBUG_PROTOCOL)
        syslog(LOG_WARNING, _("Got %s from %s (%s) for %s which is not in our node tree"),
             "DEL_SUBNET", c->name, c->hostname, name);
      return 0;
    }

  /* Check if subnet string is valid */

  if(!(s = str2net(subnetstr)))
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "DEL_SUBNET", c->name, c->hostname, _("invalid subnet string"));
      return -1;
    }

  if(seen_request(c->buffer))
    return 0;

  /* If everything is correct, delete the subnet from the list of the owner */

  s->owner = owner;

  find = lookup_subnet(owner, s);
  
  free_subnet(s);

  if(!find)
    {
      if(debug_lvl >= DEBUG_PROTOCOL)
        syslog(LOG_WARNING, _("Got %s from %s (%s) for %s which does not appear in his subnet tree"),
             "DEL_SUBNET", c->name, c->hostname, name);
      return 0;
    }
  
  /* If we are the owner of this subnet, retaliate with an ADD_SUBNET */
  
  if(owner == myself)
  {
    if(debug_lvl >= DEBUG_PROTOCOL)
      syslog(LOG_WARNING, _("Got %s from %s (%s) for ourself"), "DEL_SUBNET", c->name, c->hostname);
    send_add_subnet(c, find);
    return 0;
  }

  /* Tell the rest */
  
  for(node = connection_tree->head; node; node = node->next)
    {
      other = (connection_t *)node->data;
      if(other->status.active && other != c)
        send_request(other, "%s", c->buffer);
    }

  /* Finally, delete it. */

  subnet_del(owner, find);

cp
  return 0;
}
