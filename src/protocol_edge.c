/*
    protocol_edge.c -- handle the meta-protocol, edges
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2012 Guus Sliepen <guus@tinc-vpn.org>
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

	if(e->local_address.sa.sa_family) {
		char *local_address, *local_port;
		sockaddr2str(&e->local_address, &local_address, &local_port);

		x = send_request(c, "%d %x %s %s %s %s %x %d %s %s", ADD_EDGE, rand(),
						 e->from->name, e->to->name, address, port,
						 e->options, e->weight, local_address, local_port);
		free(local_address);
		free(local_port);
	} else {
		x = send_request(c, "%d %x %s %s %s %s %x %d", ADD_EDGE, rand(),
						 e->from->name, e->to->name, address, port,
						 e->options, e->weight);
	}

	free(address);
	free(port);

	return x;
}

bool add_edge_h(connection_t *c, const char *request) {
	edge_t *e;
	node_t *from, *to;
	char from_name[MAX_STRING_SIZE];
	char to_name[MAX_STRING_SIZE];
	char to_address[MAX_STRING_SIZE];
	char to_port[MAX_STRING_SIZE];
	char address_local[MAX_STRING_SIZE];
	char port_local[MAX_STRING_SIZE];
	sockaddr_t address, local_address = {{0}};
	uint32_t options;
	int weight;

	int parameter_count = sscanf(request, "%*d %*x "MAX_STRING" "MAX_STRING" "MAX_STRING" "MAX_STRING" %x %d "MAX_STRING" "MAX_STRING,
			                      from_name, to_name, to_address, to_port, &options, &weight, address_local, port_local);
	if (parameter_count != 6 && parameter_count != 8) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "ADD_EDGE", c->name,
			   c->hostname);
		return false;
	}

	/* Check if names are valid */

	if(!check_id(from_name) || !check_id(to_name)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s): %s", "ADD_EDGE", c->name,
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
		logger(DEBUG_PROTOCOL, LOG_WARNING,
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
	if(parameter_count >= 8)
		local_address = str2sockaddr(address_local, port_local);

	/* Check if edge already exists */

	e = lookup_edge(from, to);

	if(e) {
		bool new_address = sockaddrcmp(&e->address, &address);
		// local_address.sa.sa_family will be 0 if we got it from older tinc versions
		// local_address.sa.sa_family will be 255 (AF_UNKNOWN) if we got it from newer versions
		// but for edge which does not have local_address
		bool new_local_address = local_address.sa.sa_family && local_address.sa.sa_family != AF_UNKNOWN &&
			sockaddrcmp(&e->local_address, &local_address);

		if(e->weight == weight && e->options == options && !new_address && !new_local_address) {
			sockaddrfree(&address);
			sockaddrfree(&local_address);
			return true;
		}

		if(from == myself) {
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Got %s from %s (%s) for ourself which does not match existing entry",
					   "ADD_EDGE", c->name, c->hostname);
			send_add_edge(c, e);
			sockaddrfree(&address);
			sockaddrfree(&local_address);
			return true;
		}

		logger(DEBUG_PROTOCOL, LOG_WARNING, "Got %s from %s (%s) which does not match existing entry",
				   "ADD_EDGE", c->name, c->hostname);

		e->options = options;

		if(new_address) {
			sockaddrfree(&e->address);
			e->address = address;
		} else {
			sockaddrfree(&address);
		}

		if(new_local_address) {
			sockaddrfree(&e->local_address);
			e->local_address = local_address;
		} else {
			sockaddrfree(&local_address);
		}

		if(e->weight != weight) {
			splay_node_t *node = splay_unlink(edge_weight_tree, e);
			e->weight = weight;
			splay_insert_node(edge_weight_tree, node);
		}
	} else if(from == myself) {
		logger(DEBUG_PROTOCOL, LOG_WARNING, "Got %s from %s (%s) for ourself which does not exist",
				   "ADD_EDGE", c->name, c->hostname);
		contradicting_add_edge++;
		e = new_edge();
		e->from = from;
		e->to = to;
		send_del_edge(c, e);
		free_edge(e);
		sockaddrfree(&address);
		sockaddrfree(&local_address);
		return true;
	} else {
		e = new_edge();
		e->from = from;
		e->to = to;
		e->address = address;
		e->local_address = local_address;
		e->options = options;
		e->weight = weight;
		edge_add(e);
	}

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

bool del_edge_h(connection_t *c, const char *request) {
	edge_t *e;
	char from_name[MAX_STRING_SIZE];
	char to_name[MAX_STRING_SIZE];
	node_t *from, *to;

	if(sscanf(request, "%*d %*x "MAX_STRING" "MAX_STRING, from_name, to_name) != 2) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "DEL_EDGE", c->name,
			   c->hostname);
		return false;
	}

	/* Check if names are valid */

	if(!check_id(from_name) || !check_id(to_name)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s): %s", "DEL_EDGE", c->name,
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
		logger(DEBUG_PROTOCOL, LOG_WARNING,
		   "Ignoring indirect %s from %s (%s)",
		   "DEL_EDGE", c->name, c->hostname);
		return true;
	}

	if(!from) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Got %s from %s (%s) which does not appear in the edge tree",
				   "DEL_EDGE", c->name, c->hostname);
		return true;
	}

	if(!to) {
		logger(DEBUG_PROTOCOL, LOG_ERR, "Got %s from %s (%s) which does not appear in the edge tree",
				   "DEL_EDGE", c->name, c->hostname);
		return true;
	}

	/* Check if edge exists */

	e = lookup_edge(from, to);

	if(!e) {
		logger(DEBUG_PROTOCOL, LOG_WARNING, "Got %s from %s (%s) which does not appear in the edge tree",
				   "DEL_EDGE", c->name, c->hostname);
		return true;
	}

	if(e->from == myself) {
		logger(DEBUG_PROTOCOL, LOG_WARNING, "Got %s from %s (%s) for ourself",
				   "DEL_EDGE", c->name, c->hostname);
		contradicting_del_edge++;
		send_add_edge(c, e);    /* Send back a correction */
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
				send_del_edge(everyone, e);
			edge_del(e);
		}
	}

	return true;
}
