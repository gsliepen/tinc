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

    $Id: edge.c,v 1.1.2.5 2001/11/16 12:21:49 zarq Exp $
*/

#include "config.h"

#include <stdio.h>
#include <syslog.h>
#include <string.h>

#include <avl_tree.h>
#include <list.h>

#include "net.h"	/* Don't ask. */
#include "config.h"
#include "conf.h"
#include <utils.h>
#include "subnet.h"

#include "xalloc.h"
#include "system.h"

avl_tree_t *edge_tree;        /* Tree with all known edges (replaces active_tree) */
avl_tree_t *edge_weight_tree; /* Tree with all edges, sorted on weight */

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

int edge_name_compare(edge_t *a, edge_t *b)
{
  int result;
  char *name_a1, *name_a2, *name_b1, *name_b2;
  
  if(strcmp(a->from->name, a->to->name) < 0)
    name_a1 = a->from->name, name_a2 = a->to->name;
  else
    name_a1 = a->to->name, name_a2 = a->from->name;

  if(strcmp(b->from->name, b->to->name) < 0)
    name_b1 = b->from->name, name_b2 = b->to->name;
  else
    name_b1 = b->to->name, name_b2 = b->from->name;

  result = strcmp(name_a1, name_b1);
  
  if(result)
    return result;
  else
    return strcmp(name_a2, name_b2);
}

int edge_weight_compare(edge_t *a, edge_t *b)
{
  int result;
  
  result = a->weight - b->weight;
  
  if(result)
    return result;
  else
    return edge_name_compare(a, b);
}

void init_edges(void)
{
cp
  edge_tree = avl_alloc_tree((avl_compare_t)edge_compare, NULL);
  edge_weight_tree = avl_alloc_tree((avl_compare_t)edge_weight_compare, NULL);
cp
}

avl_tree_t *new_edge_tree(void)
{
cp
  return avl_alloc_tree((avl_compare_t)edge_name_compare, NULL);
cp
}

void free_edge_tree(avl_tree_t *edge_tree)
{
cp
  avl_delete_tree(edge_tree);
cp
}

void exit_edges(void)
{
cp
  avl_delete_tree(edge_tree);
cp
}

/* Creation and deletion of connection elements */

edge_t *new_edge(void)
{
  edge_t *e;
cp
  e = (edge_t *)xmalloc_and_zero(sizeof(*e));
cp
  return e;
}

void free_edge(edge_t *e)
{
cp
  free(e);
cp
}

void edge_add(edge_t *e)
{
cp
  avl_insert(edge_tree, e);
  avl_insert(edge_weight_tree, e);
  avl_insert(e->from->edge_tree, e);
  avl_insert(e->to->edge_tree, e);
cp
}

void edge_del(edge_t *e)
{
cp
  avl_delete(edge_tree, e);
  avl_delete(edge_weight_tree, e);
  avl_delete(e->from->edge_tree, e);
  avl_delete(e->to->edge_tree, e);
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

void dump_edges(void)
{
  avl_node_t *node;
  edge_t *e;
cp
  syslog(LOG_DEBUG, _("Edges:"));

  for(node = edge_tree->head; node; node = node->next)
    {
      e = (edge_t *)node->data;
      syslog(LOG_DEBUG, _(" %s - %s options %ld weight %d"),
             e->from->name, e->to->name, e->options, e->weight);
    }
    
  syslog(LOG_DEBUG, _("End of edges."));
cp
}
