/*
    node.c -- node tree management
    Copyright (C) 2001 Guus Sliepen <guus@sliepen.warande.net>,
                  2001 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: node.c,v 1.1.2.4 2001/10/28 22:42:49 guus Exp $
*/

#include "config.h"

#include <string.h>
#include <syslog.h>

#include <avl_tree.h>
#include "node.h"
#include "net.h"
#include <utils.h>
#include <xalloc.h>

#include "system.h"

avl_tree_t *node_tree;		/* Known nodes, sorted by name */
avl_tree_t *node_udp_tree;	/* Known nodes, sorted by address and port */

node_t *myself;

int node_compare(node_t *a, node_t *b)
{
  return strcmp(a->name, b->name);
}

int node_udp_compare(connection_t *a, connection_t *b)
{
  if(a->address < b->address)
    return -1;
  else if (a->address > b->address)
    return 1;
  else
    return a->port - b->port;
}

void init_nodes(void)
{
cp
  node_tree = avl_alloc_tree((avl_compare_t)node_compare, NULL);
  node_udp_tree = avl_alloc_tree((avl_compare_t)node_udp_compare, NULL);
cp
}

void exit_nodes(void)
{
cp
  avl_delete_tree(node_tree);
  avl_delete_tree(node_udp_tree);
cp
}

node_t *new_node(void)
{
  node_t *n = (node_t *)xmalloc_and_zero(sizeof(*n));
cp
  n->subnet_tree = new_subnet_tree();
  n->edge_tree = new_edge_tree();
  n->queue = list_alloc((list_action_t)free);
cp
  return n;
}

void free_node(node_t *n)
{
cp
  if(n->queue)
    list_delete_list(n->queue);
  if(n->name)
    free(n->name);
  if(n->hostname)
    free(n->hostname);
  if(n->key)
    free(n->key);
  if(n->subnet_tree)
    free_subnet_tree(n->subnet_tree);
  if(n->edge_tree)
    free_edge_tree(n->edge_tree);
  free(n);
cp
}

void node_add(node_t *n)
{
cp
  avl_insert(node_tree, n);
  avl_insert(node_udp_tree, n);
cp
}

void node_del(node_t *n)
{
cp
  avl_delete(node_tree, n);
  avl_delete(node_udp_tree, n);
cp
}

node_t *lookup_node(char *name)
{
  node_t n;
cp
  n.name = name;
  return avl_search(node_tree, &n);
}

node_t *lookup_node_udp(ipv4_t address, port_t port)
{
  node_t n;
cp
  n.address = address;
  n.port = port;
  return avl_search(node_udp_tree, &n);
}

void dump_nodes(void)
{
  avl_node_t *node;
  node_t *n;
cp
  syslog(LOG_DEBUG, _("Nodes:"));

  for(node = node_tree->head; node; node = node->next)
    {
      n = (node_t *)node->data;
      syslog(LOG_DEBUG, _(" %s at %s port %hd options %ld status %04x"),
             n->name, n->hostname, n->port, n->options,
             n->status);
    }
    
  syslog(LOG_DEBUG, _("End of nodes."));
cp
}
