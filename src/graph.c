/*
    graph.c -- graph algorithms
    Copyright (C) 2001-2012 Guus Sliepen <guus@tinc-vpn.org>,
                  2001-2005 Ivo Timmermans

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

   The SSSP algorithm will also be used to determine whether nodes are directly,
   indirectly or not reachable from the source. It will also set the correct
   destination address and port of a node if possible.
*/

#include "system.h"

#include "config.h"
#include "connection.h"
#include "device.h"
#include "edge.h"
#include "graph.h"
#include "list.h"
#include "logger.h"
#include "netutl.h"
#include "node.h"
#include "process.h"
#include "protocol.h"
#include "subnet.h"
#include "utils.h"
#include "xalloc.h"
#include "graph.h"

/* Implementation of Kruskal's algorithm.
   Running time: O(E)
   Please note that sorting on weight is already done by add_edge().
*/

static void mst_kruskal(void) {
	/* Clear MST status on connections */

	for list_each(connection_t, c, connection_list)
		c->status.mst = false;

	logger(DEBUG_SCARY_THINGS, LOG_DEBUG, "Running Kruskal's algorithm:");

	/* Clear visited status on nodes */

	for splay_each(node_t, n, node_tree)
		n->status.visited = false;

	/* Add safe edges */

	for splay_each(edge_t, e, edge_weight_tree) {
		if(!e->reverse || (e->from->status.visited && e->to->status.visited))
			continue;

		e->from->status.visited = true;
		e->to->status.visited = true;

		if(e->connection)
			e->connection->status.mst = true;

		if(e->reverse->connection)
			e->reverse->connection->status.mst = true;

		logger(DEBUG_SCARY_THINGS, LOG_DEBUG, " Adding edge %s - %s weight %d", e->from->name,
				   e->to->name, e->weight);
	}
}

/* Implementation of a simple breadth-first search algorithm.
   Running time: O(E)
*/

static void sssp_bfs(void) {
	list_t *todo_list = list_alloc(NULL);

	/* Clear visited status on nodes */

	for splay_each(node_t, n, node_tree) {
		n->status.visited = false;
		n->status.indirect = true;
		n->distance = -1;
	}

	/* Begin with myself */

	myself->status.visited = true;
	myself->status.indirect = false;
	myself->nexthop = myself;
	myself->prevedge = NULL;
	myself->via = myself;
	myself->distance = 0;
	list_insert_head(todo_list, myself);

	/* Loop while todo_list is filled */

	for list_each(node_t, n, todo_list) {                   /* "n" is the node from which we start */
		logger(DEBUG_SCARY_THINGS, LOG_DEBUG, " Examining edges from %s", n->name);

		if(n->distance < 0)
			abort();

		for splay_each(edge_t, e, n->edge_tree) {       /* "e" is the edge connected to "from" */
			if(!e->reverse)
				continue;

			/* Situation:

				   /
				  /
			   ----->(n)---e-->(e->to)
				  \
				   \

			   Where e is an edge, (n) and (e->to) are nodes.
			   n->address is set to the e->address of the edge left of n to n.
			   We are currently examining the edge e right of n from n:

			   - If edge e provides for better reachability of e->to, update
			     e->to and (re)add it to the todo_list to (re)examine the reachability
			     of nodes behind it.
			 */

			bool indirect = n->status.indirect || e->options & OPTION_INDIRECT;

			if(e->to->status.visited
			   && (!e->to->status.indirect || indirect)
			   && (e->to->distance != n->distance + 1 || e->weight >= e->to->prevedge->weight))
				continue;

			e->to->status.visited = true;
			e->to->status.indirect = indirect;
			e->to->nexthop = (n->nexthop == myself) ? e->to : n->nexthop;
			e->to->prevedge = e;
			e->to->via = indirect ? n->via : e->to;
			e->to->options = e->options;
			e->to->distance = n->distance + 1;

			if(!e->to->status.reachable || (e->to->address.sa.sa_family == AF_UNSPEC && e->address.sa.sa_family != AF_UNKNOWN))
				update_node_udp(e->to, &e->address);

			list_insert_tail(todo_list, e->to);
		}

		next = node->next; /* Because the list_insert_tail() above could have added something extra for us! */
		list_delete_node(todo_list, node);
	}

	list_free(todo_list);
}

static void check_reachability(void) {
	/* Check reachability status. */

	for splay_each(node_t, n, node_tree) {
		if(n->status.visited != n->status.reachable) {
			n->status.reachable = !n->status.reachable;
			n->last_state_change = time(NULL);

			if(n->status.reachable) {
				logger(DEBUG_TRAFFIC, LOG_DEBUG, "Node %s (%s) became reachable",
					   n->name, n->hostname);
			} else {
				logger(DEBUG_TRAFFIC, LOG_DEBUG, "Node %s (%s) became unreachable",
					   n->name, n->hostname);
			}

			if(experimental && OPTION_VERSION(n->options) >= 2)
				n->status.sptps = true;

			/* TODO: only clear status.validkey if node is unreachable? */

			n->status.validkey = false;
			if(n->status.sptps) {
				sptps_stop(&n->sptps);
				n->status.waitingforkey = false;
			}
			n->last_req_key = 0;

			n->status.udp_confirmed = false;
			n->maxmtu = MTU;
			n->minmtu = 0;
			n->mtuprobes = 0;

			if(timeout_initialized(&n->mtuevent))
				event_del(&n->mtuevent);

			char *name;
			char *address;
			char *port;
			char *envp[7];

			xasprintf(&envp[0], "NETNAME=%s", netname ? : "");
			xasprintf(&envp[1], "DEVICE=%s", device ? : "");
			xasprintf(&envp[2], "INTERFACE=%s", iface ? : "");
			xasprintf(&envp[3], "NODE=%s", n->name);
			sockaddr2str(&n->address, &address, &port);
			xasprintf(&envp[4], "REMOTEADDRESS=%s", address);
			xasprintf(&envp[5], "REMOTEPORT=%s", port);
			envp[6] = NULL;

			execute_script(n->status.reachable ? "host-up" : "host-down", envp);

			xasprintf(&name, n->status.reachable ? "hosts/%s-up" : "hosts/%s-down", n->name);
			execute_script(name, envp);

			free(name);
			free(address);
			free(port);

			for(int i = 0; i < 6; i++)
				free(envp[i]);

			subnet_update(n, NULL, n->status.reachable);

			if(!n->status.reachable) {
				update_node_udp(n, NULL);
				memset(&n->status, 0, sizeof n->status);
				n->options = 0;
			} else if(n->connection) {
				if(n->status.sptps) {
					if(n->connection->outgoing)
						send_req_key(n);
				} else {
					send_ans_key(n);
				}
			}
		}
	}
}

void graph(void) {
	subnet_cache_flush();
	sssp_bfs();
	check_reachability();
	mst_kruskal();
}
