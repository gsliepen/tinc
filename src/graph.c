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

    $Id: graph.c,v 1.1.2.1 2001/10/28 10:16:18 guus Exp $
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
   tree, adding safe edges until #edges = #nodes - 1.

   For the SSSP algorithm Dijkstra's seems to be a nice choice.
*/

#include <syslog.h>
#include "config.h"

#include "node.h"
#include "edge.h"
#include "connection.h"

#include "system.h"

/* Implementation of Kruskal's algorithm.
   Running time: O(V)
   Please note that sorting on weight is already done by add_vertex().
*/

void kruskal(void)
{
  avl_node_t *node;
  edge_t *e;
  node_t *n;
  connection_t *c;
  int nodes;
  int safe_edges = 0;
  
  syslog(LOG_DEBUG, _("Running Kruskal's algorithm:"));

  /* Clear MST status on nodes */

  for(node = node_tree->head; node; node = node->next)
    {
      n = (node_t *)node->data;
      n->status.mst = 0;
      node++;
    }

  /* Clear MST status on connections */

  for(node = connection_tree->head; node; node = node->next)
    {
      c = (edge_t *)node->data;
      c->status.mst = 0;
    }

  /* Add safe edges */

  for(node = edge_weight_tree->head; node; node = node->next)
    {
// Algorithm should work without this:
//      if(safe_edges = nodes - 1)
//        break;

      e = (edge_t *)node->data;
      
      if(e->from->status.mst && e->to->status.mst)
        continue;

      e->from->status.mst = 1;
      e->to->status.mst = 1;
      if(e->connection)
        e->connection->status.mst = 1;

      safe_edges++;      

      syslog(LOG_DEBUG, _("Adding safe edge %s - %s weight %d"), e->from->name, e->to->name, e->weight);
    }

  syslog(LOG_DEBUG, _("Done."));

  if(safe_edges != nodes - 1)
    {
      syslog(LOG_ERR, _("Implementation of Kruskal's algorithm is screwed: %d nodes, found %d safe edges"), nodes, safe_edges);
    }
}
