/*
    graph.c -- graph algorithms
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

    $Id: graph.c,v 1.1.2.4 2001/10/30 12:59:12 guus Exp $
*/

/* We need to generate two trees from the graph:

   1. A minimum spanning tree for broadcasts,
   2. A single-source shortest path tree for unicasts.

   Actually, the first one alone would suffice but would make unicast packets
   take longer routes than necessary.

   For the MST algorithm we can choose from Prim's or Kruskal's. I personally
   favour Kruskal's, because we make an extra AVL tree of edges sorted on
   weights (metric). That tree only has to be updated when an edge is added or
   removed, and during the MST algorithm we just have go linearly through that
   tree, adding safe edges until #edges = #nodes - 1. The implementation here
   however is not so fast, because I tried to avoid having to make a forest and
   merge trees.

   For the SSSP algorithm Dijkstra's seems to be a nice choice. Currently a
   simple breadth-first search is presented here.
*/

#include <syslog.h>
#include "config.h"
#include <string.h>

#include <avl_tree.h>

#include "node.h"
#include "edge.h"
#include "connection.h"

#include "system.h"

/* Implementation of Kruskal's algorithm.
   Running time: O(EN)
   Please note that sorting on weight is already done by add_edge().
*/

void mst_kruskal(void)
{
  avl_node_t *node;
  edge_t *e;
  node_t *n;
  connection_t *c;
  int nodes = 0;
  int safe_edges = 0;
  int skipped;

  /* Clear visited status on nodes */

  for(node = node_tree->head; node; node = node->next)
    {
      n = (node_t *)node->data;
      n->status.visited = 0;
      nodes++;
    }

  /* Starting point */
  
  ((edge_t *)edge_weight_tree->head->data)->from->status.visited = 1;

  /* Clear MST status on connections */

  for(node = connection_tree->head; node; node = node->next)
    {
      c = (connection_t *)node->data;
      c->status.mst = 0;
    }

  /* Add safe edges */

  while(safe_edges < nodes - 1)
  for(skipped = 0, node = edge_weight_tree->head; node; node = node->next)
    {
      e = (edge_t *)node->data;

      if(e->from->status.visited == e->to->status.visited)
        {
          skipped = 1;
          continue;
        }

      e->from->status.visited = 1;
      e->to->status.visited = 1;
      if(e->connection)
        e->connection->status.mst = 1;

      safe_edges++;

      if(skipped)
        break;
    }
}

/* Implementation of a simple breadth-first search algorithm.
   Running time: O(E)
*/

void sssp_bfs(void)
{
  avl_node_t *node, *from, *next, *to;
  edge_t *e;
  node_t *n, *check;
  avl_tree_t *todo_tree;

  todo_tree = avl_alloc_tree(NULL, NULL);

  /* Clear visited status on nodes */

  for(node = node_tree->head; node; node = node->next)
    {
      n = (node_t *)node->data;
      n->status.visited = 0;
    }

  /* Begin with myself */

  myself->status.visited = 1;
  myself->nexthop = myself;
  myself->via = myself;
  node = avl_alloc_node();
  node->data = myself;
  avl_insert_top(todo_tree, node);

  /* Loop while todo_tree is filled */

  while(todo_tree->head)
    {
      for(from = todo_tree->head; from; from = next)
        {
          next = from->next;
          n = (node_t *)from->data;

          for(to = n->edge_tree->head; to; to = to->next)
            {
              e = (edge_t *)to->data;

              if(e->from == n)
                check = e->to;
              else
                check = e->from;

              if(!check->status.visited)
                {
                  check->status.visited = 1;
                  check->nexthop = (n->nexthop == myself) ? check : n->nexthop;
                  check->via = check; /* FIXME: only if !(e->options & INDIRECT), otherwise use n->via */
                  node = avl_alloc_node();
                  node->data = check;
                  avl_insert_before(todo_tree, from, node);
                }
            }

           avl_delete_node(todo_tree, from);
        }
    }

  avl_free_tree(todo_tree);
}
