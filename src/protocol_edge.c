/*
    protocol_edge.c -- handle the meta-protocol, edges
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

    $Id: protocol_edge.c,v 1.1.4.7 2002/03/27 15:26:44 guus Exp $
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

int send_add_edge(connection_t *c, edge_t *e)
{
  int x;
  char *from_udpaddress, *from_udpport;
  char *to_udpaddress, *to_udpport;
cp
  sockaddr2str(&e->from.udpaddress, &from_udpaddress, &from_udpport);
  sockaddr2str(&e->to.udpaddress, &to_udpaddress, &to_udpport);
  x = send_request(c, "%d %lx %s %s %s %s %s %s %lx %d", ADD_EDGE, random(),
                      e->from.node->name, from_udpaddress, from_udpport,
		      e->to.node->name, to_udpaddress, to_udpport,
		      e->options, e->weight);
  free(from_udpaddress);
  free(from_udpport);
  free(to_udpaddress);
  free(to_udpport);
cp
  return x;
}

int add_edge_h(connection_t *c)
{
  connection_t *other;
  edge_t *e;
  node_t *from, *to;
  char from_name[MAX_STRING_SIZE];
  char to_name[MAX_STRING_SIZE];
  char from_address[MAX_STRING_SIZE];
  char from_udpport[MAX_STRING_SIZE];
  char to_address[MAX_STRING_SIZE];
  char to_udpport[MAX_STRING_SIZE];
  sockaddr_t from_udpaddress;
  sockaddr_t to_udpaddress;
  long int options;
  int weight;
  avl_node_t *node;
cp
  if(sscanf(c->buffer, "%*d %*x "MAX_STRING" "MAX_STRING" "MAX_STRING" "MAX_STRING" "MAX_STRING" "MAX_STRING" %lx %d",
            from_name, from_address, from_udpport,
	    to_name, to_address, to_udpport,
	    &options, &weight) != 8)
    {
       syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "ADD_EDGE", c->name, c->hostname);
       return -1;
    }

  /* Check if names are valid */

  if(check_id(from_name))
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "ADD_EDGE", c->name, c->hostname, _("invalid name"));
      return -1;
    }

  if(check_id(to_name))
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "ADD_EDGE", c->name, c->hostname, _("invalid name"));
      return -1;
    }

  if(seen_request(c->buffer))
    return 0;

  /* Lookup nodes */

  from = lookup_node(from_name);
  
  if(!from)
    {
      from = new_node();
      from->name = xstrdup(from_name);
      node_add(from);
    }

  to = lookup_node(to_name);
  
  if(!to)
    {
      to = new_node();
      to->name = xstrdup(to_name);
      node_add(to);
    }

  /* Convert addresses */
  
  from_udpaddress = str2sockaddr(from_address, from_udpport);
  to_udpaddress = str2sockaddr(to_address, to_udpport);

  /* Check if edge already exists */
  
  e = lookup_edge(from, to);
  
  if(e)
  {
    if(e->weight != weight || e->options != options
       || ((e->from.node == from) && (sockaddrcmp(&e->from.udpaddress, &from_udpaddress)|| sockaddrcmp(&e->to.udpaddress, &to_udpaddress)))
       || ((e->from.node == to) && (sockaddrcmp(&e->from.udpaddress, &to_udpaddress) || sockaddrcmp(&e->to.udpaddress, &from_udpaddress)))
      )
    {
      if(from == myself || to == myself)
      {
        if(debug_lvl >= DEBUG_PROTOCOL)
          syslog(LOG_WARNING, _("Got %s from %s (%s) for ourself which does not match existing entry"), "ADD_EDGE", c->name, c->hostname);
        send_add_edge(c, e);
        return 0;
      }
      else
      {
        if(debug_lvl >= DEBUG_PROTOCOL)
          syslog(LOG_WARNING, _("Got %s from %s (%s) which does not match existing entry"), "ADD_EDGE", c->name, c->hostname);
        edge_del(e);
      }
    }
    else
      return 0;
  }
  else if(from == myself || to == myself)
  {
    if(debug_lvl >= DEBUG_PROTOCOL)
      syslog(LOG_WARNING, _("Got %s from %s (%s) for ourself which does not exist"), "ADD_EDGE", c->name, c->hostname);
    e = new_edge();
    e->from.node = from;
    e->to.node = to;
    send_del_edge(c, e);
    free_edge(e);
    return 0;
  }

  e = new_edge();
  e->from.node = from;
  e->from.udpaddress = from_udpaddress;
  e->to.node = to;
  e->to.udpaddress = to_udpaddress;
  e->options = options;
  e->weight = weight;
  edge_add(e);

  /* Tell the rest about the new edge */

  for(node = connection_tree->head; node; node = node->next)
    {
      other = (connection_t *)node->data;
      if(other->status.active && other != c)
        send_request(other, "%s", c->buffer);
    }

  /* Run MST before or after we tell the rest? */

  graph();
cp
  return 0;
}

int send_del_edge(connection_t *c, edge_t *e)
{
cp
  return send_request(c, "%d %lx %s %s", DEL_EDGE, random(),
                      e->from.node->name, e->to.node->name);
}

int del_edge_h(connection_t *c)
{
  edge_t *e;
  char from_name[MAX_STRING_SIZE];
  char to_name[MAX_STRING_SIZE];
  node_t *from, *to;
  connection_t *other;
  avl_node_t *node;
cp
  if(sscanf(c->buffer, "%*d %*x "MAX_STRING" "MAX_STRING"", from_name, to_name) != 2)
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s)"), "DEL_EDGE",
             c->name, c->hostname);
      return -1;
    }

  /* Check if names are valid */

  if(check_id(from_name))
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "DEL_EDGE", c->name, c->hostname, _("invalid name"));
      return -1;
    }

  if(check_id(to_name))
    {
      syslog(LOG_ERR, _("Got bad %s from %s (%s): %s"), "DEL_EDGE", c->name, c->hostname, _("invalid name"));
      return -1;
    }

  if(seen_request(c->buffer))
    return 0;

  /* Lookup nodes */

  from = lookup_node(from_name);
  
  if(!from)
    {
      if(debug_lvl >= DEBUG_PROTOCOL)
        syslog(LOG_ERR, _("Got %s from %s (%s) which does not appear in the edge tree"), "DEL_EDGE", c->name, c->hostname);
      return 0;
    }

  to = lookup_node(to_name);
  
  if(!to)
    {
      if(debug_lvl >= DEBUG_PROTOCOL)
        syslog(LOG_ERR, _("Got %s from %s (%s) which does not appear in the edge tree"), "DEL_EDGE", c->name, c->hostname);
      return 0;
    }

  /* Check if edge exists */
  
  e = lookup_edge(from, to);
  
  if(!e)
  {
    if(debug_lvl >= DEBUG_PROTOCOL)
      syslog(LOG_WARNING, _("Got %s from %s (%s) which does not appear in the edge tree"), "DEL_EDGE", c->name, c->hostname);
    return 0;
  }

  if(e->from.node == myself || e->to.node == myself)
  {
    if(debug_lvl >= DEBUG_PROTOCOL)
      syslog(LOG_WARNING, _("Got %s from %s (%s) for ourself"), "DEL_EDGE", c->name, c->hostname);
    send_add_edge(c, e); /* Send back a correction */
    return 0;
  }

  /* Tell the rest about the deleted edge */

  for(node = connection_tree->head; node; node = node->next)
    {
      other = (connection_t *)node->data;
      if(other->status.active && other != c)
        send_request(other, "%s", c->buffer);
    }

  /* Delete the edge */
  
  edge_del(e);

  /* Run MST before or after we tell the rest? */

  graph();
cp
  return 0;
}
