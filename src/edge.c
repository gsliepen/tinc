/*
    edge.c -- edge tree management
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

    $Id: edge.c,v 1.1.2.1 2001/10/28 08:41:19 guus Exp $
*/

#include "config.h"

#include <stdio.h>
#include <syslog.h>
#include <string.h>

#include <avl_tree.h>
#include <list.h>

#include "net.h"	/* Don't ask. */
#include "netutl.h"
#include "config.h"
#include "conf.h"
#include <utils.h>
#include "subnet.h"

#include "xalloc.h"
#include "system.h"

avl_tree_t *edge_tree;        /* Tree with all known vertices (replaces active_tree) */

int edge_compare(edge_t *a, edge_t *b)
{
  int result;

  result = strcmp(a->from->name, b->from->name);
  
  if(result)
    return result;
  else
    return strcmp(a->to->name, b->to->name);
}

/* Evil edge_compare() from a parallel universe ;)

int edge_compare(edge_t *a, edge_t *b)
{
  int result;

  return (result = strcmp(a->from->name, b->from->name)) || (result = strcmp(a->to->name, b->to->name)), result;
}

*/

void init_vertices(void)
{
cp
  edge_tree = avl_alloc_tree((avl_compare_t)edge_compare, NULL);
cp
}

void exit_vertices(void)
{
cp
  avl_delete_tree(edge_tree);
cp
}

/* Creation and deletion of connection elements */

edge_t *new_edge(void)
{
cp
  edge_t *v = (edge_t *)xmalloc_and_zero(sizeof(*v));
cp
  return v;
}

void free_edge(edge_t *v)
{
cp
  free(v);
cp
}

void edge_add(edge_t *v)
{
cp
  avl_insert(edge_tree, v);
cp
}

void edge_del(edge_t *v)
{
cp
  avl_delete(edge_tree, v);
cp
}

edge_t *lookup_edge(node_t *from, node_t *to)
{
  edge_t v, *result;
cp
  v.from = from;
  v.to = to;

  result = avl_search(edge_tree, &v);

  if(result)
    return result;
cp
  v.from = to;
  v.to = from;

  return avl_search(edge_tree, &v);
}

void dump_vertices(void)
{
  avl_node_t *node;
  edge_t *v;
cp
  syslog(LOG_DEBUG, _("Vertices:"));

  for(node = edge_tree->head; node; node = node->next)
    {
      v = (edge_t *)node->data;
      syslog(LOG_DEBUG, _(" %s - %s options %ld"),
             v->from->name, v->to->name, v->options);
    }
    
  syslog(LOG_DEBUG, _("End of vertices."));
cp
}
