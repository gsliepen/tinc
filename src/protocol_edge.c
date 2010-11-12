/*
    protocol_edge.c -- handle the meta-protocol, edges
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2009 Guus Sliepen <guus@tinc-vpn.org>
                  2009      Michael Tokarev <mjt@corpit.ru>

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

#include "splay_tree.h"
#include "conf.h"
#include "connection.h"
#include "edge.h"
#include "graph.h"
#include "logger.h"
#include "meta.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"

bool send_add_edge(connection_t *c, const edge_t *e) {
	bool x;
	char *address, *port;

	sockaddr2str(&e->address, &address, &port);

	x = send_request(c, "%d %x %s %s %s %s %x %d", ADD_EDGE, rand(),
					 e->from->name, e->to->name, address, port,
					 e->options, e->weight);
	free(address);
	free(port);

	return x;
}

bool add_edge_h(connection_t *c, char *request) {
	edge_t *e;
	node_t *from, *to;
	char from_name[MAX_STRING_SIZE];
	char to_name[MAX_STRING_SIZE];
	char to_address[MAX_STRING_SIZE];
	char to_port[MAX_STRING_SIZE];
	sockaddr_t address;
	uint32_t options;
	int weight;

	if(sscanf(request, "%*d %*x "MAX_STRING" "MAX_STRING" "MAX_STRING" "MAX_STRING" %x %d",
			  from_name, to_name, to_address, to_port, &options, &weight) != 6) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "ADD_EDGE", c->name,
			   c->hostname);
		return false;
	}

	/* Check if names are valid */

	if(!check_id(from_name) || !check_id(to_name)) {
		logger(LOG_ERR, "Got bad %s from %s (%s): %s", "ADD_EDGE", c->name,
			   c->hostname, "invalid name");
		return false;
	}

	if(seen_request(request))
		return true;

	/* Lookup nodes */

	from = lookup_node(from_name);
	to = lookup_node(to_name);

	if(tunnelserver &&
	   from != myself && from != c->node &&
	   to != myself && to != c->node) {
		/* ignore indirect edge registrations for tunnelserver */
		ifdebug(PROTOCOL) logger(LOG_WARNING,
		   "Ignoring indirect %s from %s (%s)",
		   "ADD_EDGE", c->name, c->hostname);
		return true;
	}

	if(!from) {
		from = new_node();
		from->name = xstrdup(from_name);
		node_add(from);
	}

	if(!to) {
		to = new_node();
		to->name = xstrdup(to_name);
		node_add(to);
	}


	/* Convert addresses */

	address = str2sockaddr(to_address, to_port);

	/* Check if edge already exists */

	e = lookup_edge(from, to);

	if(e) {
		if(e->weight != weight || e->options != options || sockaddrcmp(&e->address, &address)) {
			if(from == myself) {
				ifdebug(PROTOCOL) logger(LOG_WARNING, "Got %s from %s (%s) for ourself which does not match existing entry",
						   "ADD_EDGE", c->name, c->hostname);
				send_add_edge(c, e);
				return true;
			} else {
				ifdebug(PROTOCOL) logger(LOG_WARNING, "Got %s from %s (%s) which does not match existing entry",
						   "ADD_EDGE", c->name, c->hostname);
				edge_del(e);
				graph();
			}
		} else
			return true;
	} else if(from == myself) {
		ifdebug(PROTOCOL) logger(LOG_WARNING, "Got %s from %s (%s) for ourself which does not exist",
				   "ADD_EDGE", c->name, c->hostname);
		contradicting_add_edge++;
		e = new_edge();
		e->from = from;
		e->to = to;
		send_del_edge(c, e);
		free_edge(e);
		return true;
	}

	e = new_edge();
	e->from = from;
	e->to = to;
	e->address = address;
	e->options = options;
	e->weight = weight;
	edge_add(e);

	/* Tell the rest about the new edge */

	if(!tunnelserver)
		forward_request(c, request);

	/* Run MST before or after we tell the rest? */

	graph();

	return true;
}

bool send_del_edge(connection_t *c, const edge_t *e) {
	return send_request(c, "%d %x %s %s", DEL_EDGE, rand(),
						e->from->name, e->to->name);
}

bool del_edge_h(connection_t *c, char *request) {
	edge_t *e;
	char from_name[MAX_STRING_SIZE];
	char to_name[MAX_STRING_SIZE];
	node_t *from, *to;

	if(sscanf(request, "%*d %*x "MAX_STRING" "MAX_STRING, from_name, to_name) != 2) {
		logger(LOG_ERR, "Got bad %s from %s (%s)", "DEL_EDGE", c->name,
			   c->hostname);
		return false;
	}

	/* Check if names are valid */

	if(!check_id(from_name) || !check_id(to_name)) {
		logger(LOG_ERR, "Got bad %s from %s (%s): %s", "DEL_EDGE", c->name,
			   c->hostname, "invalid name");
		return false;
	}

	if(seen_request(request))
		return true;

	/* Lookup nodes */

	from = lookup_node(from_name);
	to = lookup_node(to_name);

	if(tunnelserver &&
	   from != myself && from != c->node &&
	   to != myself && to != c->node) {
		/* ignore indirect edge registrations for tunnelserver */
		ifdebug(PROTOCOL) logger(LOG_WARNING,
		   "Ignoring indirect %s from %s (%s)",
		   "DEL_EDGE", c->name, c->hostname);
		return true;
	}

	if(!from) {
		ifdebug(PROTOCOL) logger(LOG_ERR, "Got %s from %s (%s) which does not appear in the edge tree",
				   "DEL_EDGE", c->name, c->hostname);
		return true;
	}

	if(!to) {
		ifdebug(PROTOCOL) logger(LOG_ERR, "Got %s from %s (%s) which does not appear in the edge tree",
				   "DEL_EDGE", c->name, c->hostname);
		return true;
	}

	/* Check if edge exists */

	e = lookup_edge(from, to);

	if(!e) {
		ifdebug(PROTOCOL) logger(LOG_WARNING, "Got %s from %s (%s) which does not appear in the edge tree",
				   "DEL_EDGE", c->name, c->hostname);
		return true;
	}

	if(e->from == myself) {
		ifdebug(PROTOCOL) logger(LOG_WARNING, "Got %s from %s (%s) for ourself",
				   "DEL_EDGE", c->name, c->hostname);
		contradicting_del_edge++;
		send_add_edge(c, e);	/* Send back a correction */
		return true;
	}

	/* Tell the rest about the deleted edge */

	if(!tunnelserver)
		forward_request(c, request);

	/* Delete the edge */

	edge_del(e);

	/* Run MST before or after we tell the rest? */

	graph();

	/* If the node is not reachable anymore but we remember it had an edge to us, clean it up */

	if(!to->status.reachable) {
		e = lookup_edge(to, myself);
		if(e) {
			if(!tunnelserver)
				send_del_edge(broadcast, e);
			edge_del(e);
		}
	}

	return true;
}
