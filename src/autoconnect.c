/*
    autoconnect.c -- automatic connection establishment
    Copyright (C) 2017 Guus Sliepen <guus@tinc-vpn.org>

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

#include "system.h"

#include "connection.h"
#include "logger.h"
#include "node.h"
#include "xalloc.h"

static void make_new_connection() {
	/* Select a random node we haven't connected to yet. */
	int count = 0;

	for splay_each(node_t, n, node_tree) {
		if(n == myself || n->connection || !(n->status.has_address || n->status.reachable)) {
			continue;
		}

		count++;
	}

	if(!count) {
		return;
	}

	int r = rand() % count;

	for splay_each(node_t, n, node_tree) {
		if(n == myself || n->connection || !(n->status.has_address || n->status.reachable)) {
			continue;
		}

		if(r--) {
			continue;
		}

		bool found = false;

		for list_each(outgoing_t, outgoing, outgoing_list) {
			if(outgoing->node == n) {
				found = true;
				break;
			}
		}

		if(!found) {
			logger(DEBUG_CONNECTIONS, LOG_INFO, "Autoconnecting to %s", n->name);
			outgoing_t *outgoing = xzalloc(sizeof(*outgoing));
			outgoing->node = n;
			list_insert_tail(outgoing_list, outgoing);
			setup_outgoing_connection(outgoing, false);
		}

		break;
	}
}

static void connect_to_unreachable() {
	/* Select a random known node. The rationale is that if there are many
	 * reachable nodes, and only a few unreachable nodes, we don't want all
	 * reachable nodes to try to connect to the unreachable ones at the
	 * same time. This way, we back off automatically. Conversely, if there
	 * are only a few reachable nodes, and many unreachable ones, we're
	 * going to try harder to connect to them. */

	int r = rand() % node_tree->count;

	for splay_each(node_t, n, node_tree) {
		if(r--) {
			continue;
		}

		/* Is it unreachable and do we know an address for it? If not, return. */
		if(n == myself || n->connection || n->status.reachable || !n->status.has_address) {
			return;
		}

		/* Are we already trying to make an outgoing connection to it? If so, return. */
		for list_each(outgoing_t, outgoing, outgoing_list) {
			if(outgoing->node == n) {
				return;
			}
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "Autoconnecting to %s", n->name);
		outgoing_t *outgoing = xzalloc(sizeof(*outgoing));
		outgoing->node = n;
		list_insert_tail(outgoing_list, outgoing);
		setup_outgoing_connection(outgoing, false);

		return;
	}
}

static void drop_superfluous_outgoing_connection() {
	/* Choose a random outgoing connection to a node that has at least one other connection. */
	int count = 0;

	for list_each(connection_t, c, connection_list) {
		if(!c->edge || !c->outgoing || !c->node || c->node->edge_tree->count < 2) {
			continue;
		}

		count++;
	}

	if(!count) {
		return;
	}

	int r = rand() % count;

	for list_each(connection_t, c, connection_list) {
		if(!c->edge || !c->outgoing || !c->node || c->node->edge_tree->count < 2) {
			continue;
		}

		if(r--) {
			continue;
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "Autodisconnecting from %s", c->name);
		list_delete(outgoing_list, c->outgoing);
		c->outgoing = NULL;
		terminate_connection(c, c->edge);
		break;
	}
}

static void drop_superfluous_pending_connections() {
	for list_each(outgoing_t, o, outgoing_list) {
		/* Only look for connections that are waiting to be retried later. */
		bool found = false;

		for list_each(connection_t, c, connection_list) {
			if(c->outgoing == o) {
				found = true;
				break;
			}
		}

		if(found) {
			continue;
		}

		logger(DEBUG_CONNECTIONS, LOG_INFO, "Cancelled outgoing connection to %s", o->node->name);
		list_delete_node(outgoing_list, node);
	}
}

void do_autoconnect() {
	/* Count number of active connections. */
	int nc = 0;

	for list_each(connection_t, c, connection_list) {
		if(c->edge) {
			nc++;
		}
	}

	/* Less than 3 connections? Eagerly try to make a new one. */
	if(nc < 3) {
		make_new_connection();
		return;
	}

	/* More than 3 connections? See if we can get rid of a superfluous one. */
	if(nc > 3) {
		drop_superfluous_outgoing_connection();
	}

	/* Drop pending outgoing connections from the outgoing list. */
	drop_superfluous_pending_connections();

	/* Check if there are unreachable nodes that we should try to connect to. */
	connect_to_unreachable();
}
