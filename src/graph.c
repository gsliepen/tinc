/*
    graph.c -- graph algorithms
    Copyright (C) 2001-2011 Guus Sliepen <guus@tinc-vpn.org>,
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

#include "splay_tree.h"
#include "config.h"
#include "connection.h"
#include "device.h"
#include "edge.h"
#include "graph.h"
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

void mst_kruskal(void) {
	splay_node_t *node, *next;
	edge_t *e;
	node_t *n;
	connection_t *c;

	/* Clear MST status on connections */

	for(node = connection_tree->head; node; node = node->next) {
		c = node->data;
		c->status.mst = false;
	}

	ifdebug(SCARY_THINGS) logger(LOG_DEBUG, "Running Kruskal's algorithm:");

	/* Clear visited status on nodes */

	for(node = node_tree->head; node; node = node->next) {
		n = node->data;
		n->status.visited = false;
	}

	/* Add safe edges */

	for(node = edge_weight_tree->head; node; node = next) {
		next = node->next;
		e = node->data;

		if(!e->reverse || (e->from->status.visited && e->to->status.visited))
			continue;

		e->from->status.visited = true;
		e->to->status.visited = true;

		if(e->connection)
			e->connection->status.mst = true;

		if(e->reverse->connection)
			e->reverse->connection->status.mst = true;

		ifdebug(SCARY_THINGS) logger(LOG_DEBUG, " Adding edge %s - %s weight %d", e->from->name,
				   e->to->name, e->weight);
	}
}

/* Implementation of Dijkstra's algorithm.
   Running time: O(N^2)
*/

static void sssp_dijkstra(void) {
	splay_node_t *node, *to;
	edge_t *e;
	node_t *n, *m;
	list_t *todo_list;
	list_node_t *lnode, *nnode;
	bool indirect;

	todo_list = list_alloc(NULL);

	ifdebug(SCARY_THINGS) logger(LOG_DEBUG, "Running Dijkstra's algorithm:");

	/* Clear visited status on nodes */

	for(node = node_tree->head; node; node = node->next) {
		n = node->data;
		n->status.visited = false;
		n->status.indirect = true;
		n->distance = -1;
	}

	/* Begin with myself */

	myself->status.indirect = false;
	myself->nexthop = myself;
	myself->via = myself;
	myself->distance = 0;
	list_insert_head(todo_list, myself);

	/* Loop while todo_list is filled */

	while(todo_list->head) {
		n = NULL;
		nnode = NULL;

		/* Select node from todo_list with smallest distance */

		for(lnode = todo_list->head; lnode; lnode = lnode->next) {
			m = lnode->data;
			if(!n || m->status.indirect < n->status.indirect || m->distance < n->distance) {
				n = m;
				nnode = lnode;
			}
		}

		/* Mark this node as visited and remove it from the todo_list */

		n->status.visited = true;
		list_unlink_node(todo_list, nnode);

		/* Update distance of neighbours and add them to the todo_list */

		for(to = n->edge_tree->head; to; to = to->next) {	/* "to" is the edge connected to "from" */
			e = to->data;

			if(e->to->status.visited || !e->reverse)
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

			   - If edge e provides for better reachability of e->to, update e->to.
			 */

			if(e->to->distance < 0)
				list_insert_tail(todo_list, e->to);

			indirect = n->status.indirect || e->options & OPTION_INDIRECT || ((n != myself) && sockaddrcmp(&n->address, &e->reverse->address));

			if(e->to->distance >= 0 && (!e->to->status.indirect || indirect) && e->to->distance <= n->distance + e->weight)
				continue;

			e->to->distance = n->distance + e->weight;
			e->to->status.indirect = indirect;
			e->to->nexthop = (n->nexthop == myself) ? e->to : n->nexthop;
			e->to->via = indirect ? n->via : e->to;
			e->to->options = e->options;

			if(e->to->address.sa.sa_family == AF_UNSPEC && e->address.sa.sa_family != AF_UNKNOWN)
				update_node_udp(e->to, &e->address);

			ifdebug(SCARY_THINGS) logger(LOG_DEBUG, " Updating edge %s - %s weight %d distance %d", e->from->name,
					   e->to->name, e->weight, e->to->distance);
		}
	}

	list_free(todo_list);
}

/* Implementation of a simple breadth-first search algorithm.
   Running time: O(E)
*/

void sssp_bfs(void) {
	splay_node_t *node, *to;
	edge_t *e;
	node_t *n;
	list_t *todo_list;
	list_node_t *from, *todonext;
	bool indirect;

	todo_list = list_alloc(NULL);

	/* Clear visited status on nodes */

	for(node = node_tree->head; node; node = node->next) {
		n = node->data;
		n->status.visited = false;
		n->status.indirect = true;
	}

	/* Begin with myself */

	myself->status.visited = true;
	myself->status.indirect = false;
	myself->nexthop = myself;
	myself->via = myself;
	list_insert_head(todo_list, myself);

	/* Loop while todo_list is filled */

	for(from = todo_list->head; from; from = todonext) {	/* "from" is the node from which we start */
		n = from->data;

		for(to = n->edge_tree->head; to; to = to->next) {	/* "to" is the edge connected to "from" */
			e = to->data;

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

			indirect = n->status.indirect || e->options & OPTION_INDIRECT;

			if(e->to->status.visited
			   && (!e->to->status.indirect || indirect))
				continue;

			e->to->status.visited = true;
			e->to->status.indirect = indirect;
			e->to->nexthop = (n->nexthop == myself) ? e->to : n->nexthop;
			e->to->via = indirect ? n->via : e->to;
			e->to->options = e->options;

			if(e->to->address.sa.sa_family == AF_UNSPEC && e->address.sa.sa_family != AF_UNKNOWN)
				update_node_udp(e->to, &e->address);

			list_insert_tail(todo_list, e->to);
		}

		todonext = from->next;
		list_delete_node(todo_list, from);
	}

	list_free(todo_list);
}

static void check_reachability(void) {
	splay_node_t *node, *next;
	node_t *n;
	char *name;
	char *address, *port;
	char *envp[7];
	int i;

	/* Check reachability status. */

	for(node = node_tree->head; node; node = next) {
		next = node->next;
		n = node->data;

		if(n->status.visited != n->status.reachable) {
			n->status.reachable = !n->status.reachable;

			if(n->status.reachable) {
				ifdebug(TRAFFIC) logger(LOG_DEBUG, "Node %s (%s) became reachable",
					   n->name, n->hostname);
			} else {
				ifdebug(TRAFFIC) logger(LOG_DEBUG, "Node %s (%s) became unreachable",
					   n->name, n->hostname);
			}

			/* TODO: only clear status.validkey if node is unreachable? */

			n->status.validkey = false;
			n->last_req_key = 0;

			n->maxmtu = MTU;
			n->minmtu = 0;
			n->mtuprobes = 0;

			if(timeout_initialized(&n->mtuevent))
				event_del(&n->mtuevent);

			xasprintf(&envp[0], "NETNAME=%s", netname ? : "");
			xasprintf(&envp[1], "DEVICE=%s", device ? : "");
			xasprintf(&envp[2], "INTERFACE=%s", iface ? : "");
			xasprintf(&envp[3], "NODE=%s", n->name);
			sockaddr2str(&n->address, &address, &port);
			xasprintf(&envp[4], "REMOTEADDRESS=%s", address);
			xasprintf(&envp[5], "REMOTEPORT=%s", port);
			envp[6] = NULL;

			execute_script(n->status.reachable ? "host-up" : "host-down", envp);

			xasprintf(&name,
					 n->status.reachable ? "hosts/%s-up" : "hosts/%s-down",
					 n->name);
			execute_script(name, envp);

			free(name);
			free(address);
			free(port);

			for(i = 0; i < 6; i++)
				free(envp[i]);

			subnet_update(n, NULL, n->status.reachable);

			if(!n->status.reachable)
				update_node_udp(n, NULL);
			else if(n->connection)
				send_ans_key(n);
		}
	}
}

void graph(void) {
	subnet_cache_flush();
	sssp_dijkstra();
	check_reachability();
	mst_kruskal();
}
