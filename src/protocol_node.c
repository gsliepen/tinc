/*
    protocol_node.c -- handle the meta-protocol, nodes
    Copyright (C) 1999-2002 Ivo Timmermans <ivo@o2w.nl>,
                  2000-2002 Guus Sliepen <guus@sliepen.eu.org>

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

    $Id: protocol_node.c,v 1.1.4.5 2002/09/04 08:33:08 guus Exp $
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

#include "system.h"

int send_add_node(connection_t *c, node_t *n)
{
  int x;
  char *address, *port;
cp
  if(!n->status.reachable)
    return 0;

  sockaddr2str(&n->address, &address, &port);
  x = send_request(c, "%d %s %s %s %lx %d %s %s", ADD_NODE,
                      n->name, address, port,
		      n->options, n->distance + 1, // Alternatively, use n->distance + c->estimated_weight
                      n->prevhop->name, n->via->name);
  free(address);
  free(port);
cp
  return x;
}

int add_node_h(connection_t *c)
{
  connection_t *other;
  node_t *n, *prevhop, *via;
  char name[MAX_STRING_SIZE];
  char address[MAX_STRING_SIZE];
  char port[MAX_STRING_SIZE];
  char prevhopname[MAX_STRING_SIZE];
  char vianame[MAX_STRING_SIZE];
  long int options;
  int distance;
  avl_node_t *node;
cp
  if(sscanf(c->buffer, "%*d "MAX_STRING" "MAX_STRING" "MAX_STRING" %lx %d "MAX_STRING" "MAX_STRING,
            name, address, port, &options, &distance, prevhopname, vianame) != 7)
    {
       syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "ADD_NODE", c->name, c->hostname);
       return -1;
    }

  /* Check if names are valid */

  if(check_id(name))
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "ADD_NODE", c->name, c->hostname, _("invalid name"));
      return -1;
    }

  /* This node is indirect if it's nexthop is as well */
  
  if(c->node->options & OPTION_INDIRECT)
    options |= OPTION_INDIRECT;

  /* Lookup nodes */

  prevhop = lookup_node(prevhopname);
  
  if(!prevhop)
    {
      prevhop = new_node();
      prevhop->name = xstrdup(prevhopname);
      node_add(prevhop);
    }

  via = lookup_node(vianame);
  
  if(!via)
    {
      via = new_node();
      via->name = xstrdup(vianame);
      node_add(via);
    }

  n = lookup_node(name);
  
  if(!n)
    {
      // It's a new node. Add it and tell the others.
      n = new_node();
      n->name = xstrdup(name);
      n->address = str2sockaddr(address, port);
      n->hostname = sockaddr2hostname(&n->address);
      n->options = options;
      n->distance = distance;
      n->nexthop = c->node;
      n->prevhop = prevhop;
      n->via = via;
      node_add(n);
      if(prevhop == myself)
        {
          syslog(LOG_WARNING, _("Got ADD_NODE %s prevhop %s via %s from %s, sending back a DEL_NODE!"), name, prevhopname, vianame, c->name);
          send_del_node(c, n);
          return 0;
        }
      n->status.reachable = 1;
    }
  else
    {
      // If this ADD_NODE is closer or more direct, use it instead of the old one.
      if(!n->status.reachable || ((n->options & OPTION_INDIRECT) && !(options & OPTION_INDIRECT)) || n->distance > distance)
        {
          if(prevhop == myself)
            {
              syslog(LOG_WARNING, _("Got ADD_NODE %s prevhop %s via %s from %s!"), name, prevhopname, vianame, c->name);
              send_del_node(c, n);
              return 0;
            }
          node = avl_unlink(node_udp_tree, n);
          n->address = str2sockaddr(address, port);
          avl_insert_node(node_udp_tree, node);
          if(n->hostname)
            free(n->hostname);
          n->hostname = sockaddr2hostname(&n->address);
          n->options = options;
          n->distance = distance;
          n->via = n->nexthop = c->node;
          n->status.reachable = 1;
          n->status.validkey = 0;
          n->status.waitingforkey = 0;
        }
      else
        // Otherwise, just ignore it.
        return 0;
    }

  /* Tell the rest about the new node */

  for(node = connection_tree->head; node; node = node->next)
    {
      other = (connection_t *)node->data;
      if(other->status.active && other != c)
        send_add_node(other, n);
    }

cp
  return 0;
}

int send_del_node(connection_t *c, node_t *n)
{
cp
  return send_request(c, "%d %s %s", DEL_NODE, n->name, n->prevhop->name);
}

int del_node_h(connection_t *c)
{
  char name[MAX_STRING_SIZE];
  char prevhopname[MAX_STRING_SIZE];
  node_t *n, *prevhop;
  connection_t *other;
  avl_node_t *node;
cp
  if(sscanf(c->buffer, "%*d "MAX_STRING" "MAX_STRING, name, prevhopname) != 2)
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "DEL_NODE",
             c->name, c->hostname);
      return -1;
    }

  /* Check if names are valid */

  if(check_id(name))
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "DEL_NODE", c->name, c->hostname, _("invalid name"));
      return -1;
    }

  /* Lookup nodes */

  n = lookup_node(name);
  prevhop = lookup_node(prevhopname);

  if(!n || !prevhop)
    {
      if(debug_lvl >= DEBUG_PROTOCOL)
        syslog(LOG_WARNING, _("Got %s from %s (%s) which does not appear in the node tree"), "DEL_NODE", c->name, c->hostname);
      return 0;
    }

  /* If we got a DEL_NODE but we know of a different route to it, tell the one who send the DEL_NODE */

  if(n->nexthop != c->node || n->prevhop != prevhop)
    {
      return send_add_node(c, n);
    }
  
  /* Otherwise, tell the rest about the deleted node */

  for(node = connection_tree->head; node; node = node->next)
    {
      other = (connection_t *)node->data;
      if(other->status.active && other != c)
        send_del_node(other, n);
    }

  /* "Delete" the node */
  
  n->status.reachable = 0;
  n->status.validkey = 0;
cp
  return 0;
}
